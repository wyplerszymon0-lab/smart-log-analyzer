#!/usr/bin/env python3
"""
smart-log-analyzer CLI

Usage:
    python main.py <log_file> [--format md|json] [--ai] [--output FILE]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Analyze server logs and detect anomalies. Optionally generate AI summaries.",
    )
    p.add_argument("log_file", type=Path, help="Path to the log file (nginx or app logs)")
    p.add_argument(
        "--format",
        choices=["md", "json"],
        default="md",
        help="Output format: markdown (default) or json",
    )
    p.add_argument(
        "--ai",
        action="store_true",
        help="Use OpenAI to generate a human-readable incident summary (requires OPENAI_API_KEY)",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write output to file instead of stdout",
    )
    p.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="OpenAI model to use for summary (default: gpt-4o-mini)",
    )
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    log_path: Path = args.log_file
    if not log_path.exists():
        print(f"[error] File not found: {log_path}", file=sys.stderr)
        return 1

    print(f"[*] Analyzing {log_path} ...", file=sys.stderr)

    # --- core analysis ---
    from src.analyzer import analyze
    report = analyze(log_path)

    print(
        f"[*] Parsed {report.parsed_lines}/{report.total_lines} lines, "
        f"{len(report.anomalies)} anomalies found.",
        file=sys.stderr,
    )

    # --- optional AI summary ---
    if args.ai:
        print("[*] Requesting AI summary from OpenAI ...", file=sys.stderr)
        try:
            from src.ai_summary import generate_summary
            generate_summary(report, model=args.model)
            print("[*] AI summary attached.", file=sys.stderr)
        except Exception as exc:
            print(f"[warn] AI summary failed: {exc}", file=sys.stderr)

    # --- render ---
    from src.reporter import to_markdown, to_json
    output = to_markdown(report) if args.format == "md" else to_json(report)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"[*] Report saved to {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
