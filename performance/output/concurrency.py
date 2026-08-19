"""Console output for the `concurrency` command."""

from __future__ import annotations

from ..benchmark_suite import ConcurrencyResult
from .layout import Column, banner, print_table, rule
from .theme import muted


def print_concurrency_header() -> None:
    banner("CONCURRENCY BENCHMARK")
    print(
        muted(
            "\nNote: CPython's GIL means pure-Python parsing work will not scale\n"
            "linearly with threads the way I/O-bound work would. This measures\n"
            "whether shared state (lru_cache locks, etc.) becomes a contention\n"
            "bottleneck under concurrent load -- not a parallel-speedup claim.\n"
        )
    )


def print_concurrency_summary(results: list[ConcurrencyResult]) -> None:
    banner("CONCURRENCY SUMMARY", width=90)

    columns = [
        Column("Parser", 15),
        Column("Dataset", 18),
        Column("Operation", 14),
        Column("Workers", 10, ">"),
        Column("URLs/sec", 16, ">"),
    ]

    rows = [
        [result.parser, result.dataset, result.operation, str(workers), f"{urls_per_second:,.1f}"]
        for result in results
        for workers, urls_per_second in zip(result.worker_counts, result.urls_per_second)
    ]

    print_table(columns, rows)
    rule(width=90)
