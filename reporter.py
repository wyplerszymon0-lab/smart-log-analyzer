"""
reporter.py — renders an AnalysisReport to Markdown or JSON.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from analyzer import AnalysisReport


def _fmt_time(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "unknown"


def to_markdown(report: "AnalysisReport") -> str:
    lines: list[str] = []

    lines.append("# 📋 Log Analysis Report\n")
    lines.append(f"**Source:** `{report.source}`  ")
    lines.append(f"**Generated:** {_fmt_time(datetime.utcnow())} UTC\n")

    lines.append("## Overview\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total log entries | {report.total_lines:,} |")
    lines.append(f"| Successfully parsed | {report.parsed_lines:,} |")
    lines.append(f"| Time range | {_fmt_time(report.time_range[0])} → {_fmt_time(report.time_range[1])} |")
    lines.append(f"| Error rate | {report.error_rate:.2%} |")
    if report.avg_response_ms is not None:
        lines.append(f"| Avg response time | {report.avg_response_ms:.0f} ms |")
    lines.append("")

    if report.anomalies:
        lines.append("## ⚠️ Anomalies Detected\n")
        for a in report.anomalies:
            emoji = "🔴" if a.severity == "critical" else "🟡"
            lines.append(f"### {emoji} `{a.kind}` — {a.severity.upper()}\n")
            lines.append(f"{a.description}  ")
            lines.append(f"**Count:** {a.count}\n")
            if a.evidence:
                lines.append("**Evidence:**")
                for ev in a.evidence:
                    lines.append(f"```\n{ev}\n```")
            lines.append("")
    else:
        lines.append("## ✅ No Anomalies Detected\n")

    lines.append("## HTTP Status Distribution\n")
    lines.append("| Status | Count |")
    lines.append("|--------|-------|")
    for code, n in sorted(report.status_distribution.items()):
        lines.append(f"| {code} | {n:,} |")
    lines.append("")

    lines.append("## Top 10 Paths\n")
    lines.append("| Path | Hits |")
    lines.append("|------|------|")
    for path, n in report.top_paths:
        lines.append(f"| `{path}` | {n:,} |")
    lines.append("")

    lines.append("## Top 10 IPs\n")
    lines.append("| IP | Requests |")
    lines.append("|----|----------|")
    for ip, n in report.top_ips:
        lines.append(f"| `{ip}` | {n:,} |")
    lines.append("")

    if report.summary:
        lines.append("## 🤖 AI Incident Summary\n")
        lines.append(report.summary)
        lines.append("")

    return "\n".join(lines)


def to_json(report: "AnalysisReport") -> str:
    data = {
        "source": report.source,
        "total_lines": report.total_lines,
        "parsed_lines": report.parsed_lines,
        "time_range": [_fmt_time(report.time_range[0]), _fmt_time(report.time_range[1])],
        "error_rate": round(report.error_rate, 4),
        "avg_response_ms": report.avg_response_ms,
        "status_distribution": {str(k): v for k, v in report.status_distribution.items()},
        "top_paths": [{"path": p, "count": n} for p, n in report.top_paths],
        "top_ips": [{"ip": ip, "count": n} for ip, n in report.top_ips],
        "anomalies": [
            {
                "kind": a.kind,
                "severity": a.severity,
                "description": a.description,
                "count": a.count,
                "evidence": a.evidence,
            }
            for a in report.anomalies
        ],
        "ai_summary": report.summary or None,
    }
    return json.dumps(data, indent=2)
