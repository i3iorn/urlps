"""
Aggregate end-of-run `benchmark` summary: errors/memory/cache broken down
and totaled across the whole run.

Deliberately does *not* re-print every individual result -- that already
streamed live via LiveProgress as the suite ran; repeating it here would
just be the same table twice.
"""

from __future__ import annotations

import statistics

from ..benchmark_suite import BenchmarkResult
from .layout import Column, banner, bar, print_table, section
from .theme import CHECK, Ansi, bad, muted, ok, style


def print_summary(results: list[BenchmarkResult]) -> None:
    banner("SUMMARY", width=90)
    _print_overview(results)

    _print_error_summary(results)
    _print_memory_summary(results)
    _print_cache_summary(results)


def _print_overview(results: list[BenchmarkResult]) -> None:
    parsers = {result.parser for result in results}
    datasets = {result.dataset for result in results}
    operations = {result.operation for result in results}

    total_urls = sum(result.urls for result in results)
    total_ok = sum(result.successful for result in results)
    total_fail = sum(result.failed for result in results)
    success_fraction = (total_ok / total_urls) if total_urls else 0.0

    print(
        f"\n{style(f'{len(results):,}', Ansi.BOLD)} results  "
        f"{muted(f'({len(parsers)} parser(s), {len(datasets)} dataset(s), {len(operations)} operation(s))')}"
    )
    print(f"{total_urls:,} URLs  {bar(success_fraction, width=30)}  "
          f"{ok(f'{total_ok:,} ok')}, {bad(f'{total_fail:,} failed') if total_fail else muted('0 failed')}")


def _print_error_summary(results: list[BenchmarkResult]) -> None:
    section("ERROR SUMMARY")

    error_counter: dict[tuple[str, str, str], int] = {}

    for result in results:
        for error_type, count in result.errors.by_type.items():
            key = (result.parser, result.operation, error_type)
            error_counter[key] = error_counter.get(key, 0) + count

    if not error_counter:
        print(f"{ok(CHECK)} No errors recorded.")
        return

    columns = [
        Column("Parser", 15),
        Column("Operation", 21),
        Column("Error type", 31),
        Column("Count", 5, ">"),
    ]

    rows = [
        [parser, operation, error_type, str(count)]
        for (parser, operation, error_type), count in sorted(error_counter.items())
    ]

    print_table(columns, rows)


def _print_memory_summary(results: list[BenchmarkResult]) -> None:
    """
    Worst-case peak / average bytes-per-URL / average object count, per
    parser+operation, across every dataset in this run.
    """
    with_memory = [result for result in results if result.memory]
    if not with_memory:
        return

    section("MEMORY (peak allocated / URL / object count, by parser+operation, this run)")

    columns = [
        Column("Parser", 15),
        Column("Operation", 22),
        Column("Peak KB", 14, ">"),
        Column("Bytes/URL", 14, ">"),
        Column("Objects", 12, ">"),
    ]

    totals: dict[tuple[str, str], dict[str, list[float]]] = {}

    for result in with_memory:
        key = (result.parser, result.operation)
        bucket = totals.setdefault(key, {"peak": [], "bytes_per_url": [], "objects": []})
        bucket["peak"].append(result.memory["peak_bytes"])
        bucket["bytes_per_url"].append(result.memory["bytes_per_url"])
        bucket["objects"].append(result.memory["object_count"])

    rows = [
        [
            parser,
            operation,
            f"{max(bucket['peak']) / 1024:,.1f}",
            f"{statistics.mean(bucket['bytes_per_url']):,.1f}",
            f"{statistics.mean(bucket['objects']):,.0f}",
        ]
        for (parser, operation), bucket in sorted(totals.items())
    ]

    print_table(columns, rows)


def _hit_rate_color(pct: float) -> str:
    if pct >= 90.0:
        return Ansi.GREEN
    if pct >= 60.0:
        return Ansi.YELLOW
    return Ansi.RED


def _print_cache_summary(results: list[BenchmarkResult]) -> None:
    with_cache = [result for result in results if result.cache_delta]
    if not with_cache:
        return

    section("CACHE HIT RATES (this run, by parser)")

    totals: dict[str, tuple[int, int]] = {}

    for result in with_cache:
        for category, caches in result.cache_delta.items():
            for cache_name, stats in caches.items():
                key = f"{result.parser}:{category}.{cache_name}"
                hits, misses = totals.get(key, (0, 0))
                totals[key] = (hits + stats["hits"], misses + stats["misses"])

    columns = [
        Column("Cache", 45),
        Column("Hits", 12, ">"),
        Column("Misses", 12, ">"),
        Column("Hit rate", 10, ">"),
    ]

    rows = []
    for key, (hits, misses) in sorted(totals.items()):
        total = hits + misses
        rate_pct = (hits / total * 100) if total else None
        rate_text = f"{rate_pct:.1f}%" if rate_pct is not None else "n/a"

        if rate_pct is not None:
            # Pad to the column width *before* coloring: print_table() right-
            # aligns this cell again, but by then it's long enough (visible
            # text + ANSI bytes) that the second pass is a no-op -- Python's
            # `:>N` never truncates, only pads shorter strings.
            rate_text = style(f"{rate_text:>10}", _hit_rate_color(rate_pct))

        rows.append([key, f"{hits:,}", f"{misses:,}", rate_text])

    print_table(columns, rows)
