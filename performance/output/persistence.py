"""JSON result-file writers, shared by `benchmark` and `concurrency`."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..benchmark_suite import BenchmarkResult, ConcurrencyResult


def _write_json(payload: dict[str, Any], path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(payload, indent=2, default=str),
        encoding="utf-8",
    )

    return path


def save_results(results: list[BenchmarkResult], path: str | Path) -> Path:
    """Serialize benchmark results to JSON."""
    return _write_json(
        {
            "results": [result.as_dict() for result in results],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        path,
    )


def save_concurrency_results(results: list[ConcurrencyResult], path: str | Path) -> Path:
    """Serialize concurrency benchmark results to JSON."""
    return _write_json(
        {
            "results": [result.as_dict() for result in results],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        path,
    )
