"""Tests for the log analyzer core logic."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.analyzer import parse_line, analyze


NGINX_LINE = (
    '192.168.1.1 - - [15/Jan/2024:08:00:01 +0000] '
    '"GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0" 0.250'
)

APP_LINE = "2024-01-15 08:00:01 ERROR  database connection pool exhausted"


def test_parse_nginx_line():
    entry = parse_line(NGINX_LINE)
    assert entry.ip == "192.168.1.1"
    assert entry.method == "GET"
    assert entry.path == "/api/users"
    assert entry.status == 200
    assert entry.response_time_ms == 250.0
    print("✓ nginx line parsed correctly")


def test_parse_app_line():
    entry = parse_line(APP_LINE)
    assert entry.level == "ERROR"
    assert "pool exhausted" in entry.message
    print("✓ app log line parsed correctly")


def test_analyze_sample(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        NGINX_LINE + "\n" +
        '10.0.0.1 - - [15/Jan/2024:08:00:02 +0000] "GET /bad HTTP/1.1" 500 64 "-" "curl" 5.000\n' * 20
    )
    report = analyze(log)
    assert report.total_lines == 21
    assert any(a.kind == "error_spike" for a in report.anomalies)
    print("✓ error_spike anomaly detected correctly")


if __name__ == "__main__":
    import tempfile, os
    test_parse_nginx_line()
    test_parse_app_line()
    with tempfile.TemporaryDirectory() as d:
        test_analyze_sample(Path(d))
    print("\nAll tests passed.")
