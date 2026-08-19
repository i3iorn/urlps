"""Loading benchmark results and small HTML-escaping helpers."""

from __future__ import annotations

import html
import json
from pathlib import Path

PERFORMANCE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = PERFORMANCE_DIR / "benchmark_results.json"
OUTPUT_FILE = PERFORMANCE_DIR / "performance_report.html"


def load_results(path: str | Path = INPUT_FILE) -> list[dict]:
    with Path(path).open("r", encoding="utf-8") as fh:
        payload = json.load(fh)

    return payload.get("results", [])


def esc(value: object) -> str:
    return html.escape(str(value))


def fmt_rate(value: float) -> str:
    """parses_per_second can be `inf` when elapsed_seconds rounds to 0."""
    if value == float("inf"):
        return "∞"  # infinity symbol
    return f"{value:,.1f}"
