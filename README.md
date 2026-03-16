# smart-log-analyzer 

A lightweight CLI tool that parses server logs (nginx, generic app), detects anomalies automatically, and generates AI-powered incident summaries via OpenAI.

## Why it exists

Digging through thousands of log lines to find what went wrong is tedious. This tool does the boring part — parsing, counting, pattern matching — and optionally asks GPT to write the incident summary for you.

## Features

- Parses **nginx Combined Log Format** and generic **structured app logs**
- Detects 4 anomaly types out-of-the-box:
  - `error_spike` — unusually high 5xx / ERROR rate
  - `slow_requests` — p95 response time exceeds threshold
  - `ip_flood` — single IP making hundreds of requests
  - `404_storm` — scanner or broken-link storm
- Outputs **Markdown** (default) or **JSON**
- Optional **GPT-4o-mini AI summary** — executive summary + recommended actions
- Zero heavy dependencies (only `openai` for the AI feature)

## Quick start

```bash
git clone https://github.com/yourname/smart-log-analyzer
cd smart-log-analyzer
pip install -r requirements.txt

# Basic analysis (no AI)
python main.py examples/sample_nginx.log

# With AI summary
export OPENAI_API_KEY=sk-...
python main.py examples/sample_nginx.log --ai

# Save JSON report
python main.py access.log --format json --output report.json

# Use a bigger model
python main.py access.log --ai --model gpt-4o
```

## Example output

```markdown
#  Log Analysis Report

**Source:** `access.log`

## Overview
| Metric        | Value     |
|---------------|-----------|
| Total entries | 12,847    |
| Error rate    | 23.40%    |
| Avg response  | 340 ms    |

##  Anomalies Detected

###  `error_spike` — CRITICAL
Error rate is 23.4% (3,006/12,847 entries)

###  AI Incident Summary
**Executive summary:** The service experienced a critical error spike...
```

## Architecture

```
main.py               ← CLI entry point (argparse)
src/
  analyzer.py         ← log parsing + anomaly detection (pure Python)
  ai_summary.py       ← OpenAI integration
  reporter.py         ← Markdown / JSON rendering
examples/
  sample_nginx.log    ← sample file for testing
tests/
  test_analyzer.py    ← unit tests (no external deps)
```

## Running tests

```bash
python tests/test_analyzer.py
```

## Extending

Add a new anomaly detector in `analyzer.py` — just write a function with signature `(entries: list[LogEntry]) -> Anomaly | None` and append it to the `DETECTORS` list.

## Tech stack

- **Python 3.10+** — standard library only for core logic
- **openai** — optional AI summary feature
