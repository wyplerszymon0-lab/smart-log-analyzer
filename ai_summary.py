"""
ai_summary.py — uses OpenAI to produce a human-readable incident summary
from a structured AnalysisReport.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from analyzer import AnalysisReport


def _report_to_context(report: "AnalysisReport") -> str:
    lines = [
        f"Log file: {report.source}",
        f"Total entries: {report.total_lines} ({report.parsed_lines} parsed)",
    ]
    if report.time_range[0]:
        lines.append(f"Time range: {report.time_range[0]} → {report.time_range[1]}")
    lines.append(f"Error rate: {report.error_rate:.1%}")
    if report.avg_response_ms is not None:
        lines.append(f"Avg response time: {report.avg_response_ms:.0f}ms")

    lines.append("\nHTTP status distribution:")
    for code, n in sorted(report.status_distribution.items()):
        lines.append(f"  {code}: {n}")

    lines.append("\nTop 5 paths:")
    for path, n in report.top_paths[:5]:
        lines.append(f"  {path}  ({n} hits)")

    lines.append("\nTop 5 IPs:")
    for ip, n in report.top_ips[:5]:
        lines.append(f"  {ip}  ({n} requests)")

    if report.anomalies:
        lines.append(f"\nAnomalies detected ({len(report.anomalies)}):")
        for a in report.anomalies:
            lines.append(f"  [{a.severity.upper()}] {a.kind}: {a.description}")
            for ev in a.evidence[:3]:
                lines.append(f"    • {ev}")

    return "\n".join(lines)


SYSTEM_PROMPT = """\
You are an expert SRE (Site Reliability Engineer) analyst.
You will receive structured metrics from a server log file.
Write a concise incident/health report with:
1. A one-sentence executive summary.
2. Key findings (bullet points, max 5).
3. Recommended actions (bullet points, max 4).
Keep the tone professional and direct. No fluff. Max 300 words.
"""


def generate_summary(report: "AnalysisReport", model: str = "gpt-4o-mini") -> str:
    """
    Calls OpenAI and attaches the generated summary to report.summary.
    Returns the summary string.
    Raises RuntimeError if OPENAI_API_KEY is not set.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set.")

    try:
        from openai import OpenAI
    except ImportError as exc:
        raise ImportError("openai package not installed. Run: pip install openai") from exc

    client = OpenAI(api_key=api_key)
    context = _report_to_context(report)

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": context},
        ],
        temperature=0.3,
        max_tokens=600,
    )

    summary = response.choices[0].message.content.strip()
    report.summary = summary
    return summary
