"""
smart-log-analyzer — core analysis engine
Parses nginx/app logs, detects anomalies, returns structured findings.
"""

from __future__ import annotations

import re
import json
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class LogEntry:
    raw: str
    timestamp: datetime | None
    level: str | None          # ERROR, WARN, INFO, DEBUG
    ip: str | None
    method: str | None
    path: str | None
    status: int | None
    response_time_ms: float | None
    message: str


@dataclass
class Anomaly:
    kind: str          # e.g. "error_spike", "slow_requests", "ip_flood"
    severity: str      # "critical" | "warning" | "info"
    description: str
    evidence: list[str] = field(default_factory=list)
    count: int = 0


@dataclass
class AnalysisReport:
    source: str
    total_lines: int
    parsed_lines: int
    time_range: tuple[datetime | None, datetime | None]
    error_rate: float
    top_paths: list[tuple[str, int]]
    top_ips: list[tuple[str, int]]
    status_distribution: dict[int, int]
    avg_response_ms: float | None
    anomalies: list[Anomaly]
    summary: str = ""            # filled by AI layer


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

# Combined Log Format (nginx default)
_NGINX_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) \d+ "[^"]*" "[^"]*"'
    r'(?:\s+(?P<rt>[\d.]+))?'
)

# Generic app log: 2024-01-15 12:34:56 ERROR  something bad happened
_APP_RE = re.compile(
    r'(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
    r'\s+(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL)'
    r'\s+(?P<msg>.+)'
)

_TIME_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
]


def _parse_time(raw: str) -> datetime | None:
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    return None


def parse_line(line: str) -> LogEntry:
    line = line.rstrip()

    m = _NGINX_RE.match(line)
    if m:
        return LogEntry(
            raw=line,
            timestamp=_parse_time(m.group("time")),
            level=None,
            ip=m.group("ip"),
            method=m.group("method"),
            path=m.group("path"),
            status=int(m.group("status")),
            response_time_ms=float(m.group("rt")) * 1000 if m.group("rt") else None,
            message=line,
        )

    m = _APP_RE.match(line)
    if m:
        return LogEntry(
            raw=line,
            timestamp=_parse_time(m.group("time")),
            level=m.group("level").upper().replace("WARNING", "WARN"),
            ip=None,
            method=None,
            path=None,
            status=None,
            response_time_ms=None,
            message=m.group("msg"),
        )

    return LogEntry(
        raw=line,
        timestamp=None,
        level=None,
        ip=None,
        method=None,
        path=None,
        status=None,
        response_time_ms=None,
        message=line,
    )


def iter_entries(path: Path) -> Iterator[LogEntry]:
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                yield parse_line(line)


# ---------------------------------------------------------------------------
# Anomaly detectors
# ---------------------------------------------------------------------------

def _detect_error_spike(entries: list[LogEntry], threshold: float = 0.15) -> Anomaly | None:
    total = len(entries)
    if total == 0:
        return None
    errors = [e for e in entries if (e.status and e.status >= 500) or e.level in ("ERROR", "CRITICAL", "FATAL")]
    rate = len(errors) / total
    if rate >= threshold:
        samples = [e.raw[:120] for e in errors[:5]]
        return Anomaly(
            kind="error_spike",
            severity="critical" if rate > 0.3 else "warning",
            description=f"Error rate is {rate:.1%} ({len(errors)}/{total} entries)",
            evidence=samples,
            count=len(errors),
        )
    return None


def _detect_slow_requests(entries: list[LogEntry], p95_threshold_ms: float = 2000) -> Anomaly | None:
    times = [e.response_time_ms for e in entries if e.response_time_ms is not None]
    if len(times) < 10:
        return None
    times.sort()
    p95 = times[int(len(times) * 0.95)]
    slow = [e for e in entries if e.response_time_ms and e.response_time_ms > p95_threshold_ms]
    if p95 > p95_threshold_ms:
        return Anomaly(
            kind="slow_requests",
            severity="warning",
            description=f"p95 response time is {p95:.0f}ms (threshold: {p95_threshold_ms:.0f}ms)",
            evidence=[e.raw[:120] for e in slow[:5]],
            count=len(slow),
        )
    return None


def _detect_ip_flood(entries: list[LogEntry], threshold: int = 500) -> Anomaly | None:
    counts: Counter = Counter(e.ip for e in entries if e.ip)
    flooded = [(ip, n) for ip, n in counts.most_common(10) if n >= threshold]
    if flooded:
        return Anomaly(
            kind="ip_flood",
            severity="critical",
            description=f"{len(flooded)} IP(s) made {flooded[0][1]}+ requests",
            evidence=[f"{ip}: {n} requests" for ip, n in flooded],
            count=sum(n for _, n in flooded),
        )
    return None


def _detect_404_storm(entries: list[LogEntry], threshold: int = 100) -> Anomaly | None:
    not_found = [e for e in entries if e.status == 404]
    if len(not_found) >= threshold:
        paths = Counter(e.path for e in not_found if e.path).most_common(5)
        return Anomaly(
            kind="404_storm",
            severity="warning",
            description=f"{len(not_found)} 404 responses detected — possible scanner or broken links",
            evidence=[f"{p}: {n}x" for p, n in paths],
            count=len(not_found),
        )
    return None


DETECTORS = [_detect_error_spike, _detect_slow_requests, _detect_ip_flood, _detect_404_storm]


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze(path: Path) -> AnalysisReport:
    entries = list(iter_entries(path))
    total = len(entries)
    parsed = sum(1 for e in entries if e.timestamp or e.status or e.level)

    timestamps = sorted(e.timestamp for e in entries if e.timestamp)
    time_range = (timestamps[0] if timestamps else None, timestamps[-1] if timestamps else None)

    error_entries = [e for e in entries if (e.status and e.status >= 500) or e.level in ("ERROR", "CRITICAL", "FATAL")]
    error_rate = len(error_entries) / total if total else 0.0

    path_counter: Counter = Counter(e.path for e in entries if e.path)
    ip_counter: Counter = Counter(e.ip for e in entries if e.ip)
    status_dist: dict[int, int] = defaultdict(int)
    for e in entries:
        if e.status:
            status_dist[e.status] += 1

    rt_values = [e.response_time_ms for e in entries if e.response_time_ms is not None]
    avg_rt = sum(rt_values) / len(rt_values) if rt_values else None

    anomalies = [a for det in DETECTORS if (a := det(entries)) is not None]

    return AnalysisReport(
        source=str(path),
        total_lines=total,
        parsed_lines=parsed,
        time_range=time_range,
        error_rate=error_rate,
        top_paths=path_counter.most_common(10),
        top_ips=ip_counter.most_common(10),
        status_distribution=dict(status_dist),
        avg_response_ms=avg_rt,
        anomalies=anomalies,
    )
