"""
Aggregation for the HTML report.

Everything below only reshapes/sums the numbers that are already in each
result row. Nothing here computes a ratio, percent difference, or "winner"
between parsers -- when multiple parsers are present, the report puts their
raw numbers side by side (same chart, same table) and leaves the reading of
them to the viewer.
"""

from __future__ import annotations

import statistics
from collections import defaultdict


def per_parser_summary(results: list[dict]) -> list[dict]:
    """Aggregate raw totals per parser (no cross-parser math)."""
    totals: dict[str, dict] = {}

    for result in results:
        parser = result["parser"]
        bucket = totals.setdefault(
            parser,
            {"parser": parser, "urls": 0, "successful": 0, "failed": 0, "elapsed_seconds": 0.0},
        )
        bucket["urls"] += result["urls"]
        bucket["successful"] += result["successful"]
        bucket["failed"] += result["failed"]
        bucket["elapsed_seconds"] += result["elapsed_seconds"]

    summary = []
    for bucket in totals.values():
        urls = bucket["urls"]
        elapsed = bucket["elapsed_seconds"]
        summary.append(
            {
                "parser": bucket["parser"],
                "urls": urls,
                "successful": bucket["successful"],
                "failed": bucket["failed"],
                "success_rate": (bucket["successful"] / urls * 100.0) if urls else 0.0,
                "microseconds_per_url": (elapsed / urls * 1_000_000.0) if urls else 0.0,
                "parses_per_second": (urls / elapsed) if elapsed else float("inf"),
            }
        )

    return sorted(summary, key=lambda row: row["parser"])


def _timing_stats(extra: dict) -> tuple[float | None, float | None, float | None]:
    """
    (min_ms, max_ms, mean_ms) across the repeated timing passes behind one
    result's headline number -- how much the measurement jittered run to
    run. `benchmark_operation()` results carry min/max/mean directly;
    `benchmark_repeated_parse()` results only carry the raw timing list, so
    derive it from that instead of leaving repeated-parse rows blank.
    """
    if "min_seconds" in extra:
        return (
            extra["min_seconds"] * 1000,
            extra["max_seconds"] * 1000,
            extra["mean_seconds"] * 1000,
        )

    timings = extra.get("all_timings_seconds")
    if timings:
        return min(timings) * 1000, max(timings) * 1000, statistics.mean(timings) * 1000

    return None, None, None


def timing_rows(results: list[dict]) -> list[dict]:
    """One row per result: throughput + how stable the repeats were."""
    rows = []

    for result in results:
        min_ms, max_ms, mean_ms = _timing_stats(result.get("extra") or {})

        jitter_pct = None
        if min_ms is not None and max_ms is not None and mean_ms:
            jitter_pct = (max_ms - min_ms) / mean_ms * 100.0

        rows.append(
            {
                "parser": result["parser"],
                "dataset": result["dataset"],
                "operation": result["operation"],
                "urls": result["urls"],
                "successful": result["successful"],
                "failed": result["failed"],
                "success_rate": result["success_rate"],
                "elapsed_ms": result["elapsed_seconds"] * 1000,
                "microseconds_per_url": result["microseconds_per_url"],
                "parses_per_second": result["parses_per_second"],
                "min_ms": min_ms,
                "max_ms": max_ms,
                "mean_ms": mean_ms,
                "jitter_pct": jitter_pct,
            }
        )

    return rows


def relative_speed_rows(results: list[dict]) -> list[dict]:
    """
    Per operation, each parser's URL-weighted mean µs/URL plus how many
    times slower it is than the fastest parser for that same operation
    (1.00x = fastest). This is the only place the report compares parsers
    directly against each other -- everywhere else raw numbers are put
    side by side and left to the viewer.
    """
    totals: dict[tuple[str, str], dict[str, float]] = {}

    for result in results:
        key = (result["operation"], result["parser"])
        bucket = totals.setdefault(key, {"weighted_us": 0.0, "urls": 0.0})
        bucket["weighted_us"] += result["microseconds_per_url"] * result["urls"]
        bucket["urls"] += result["urls"]

    per_operation: dict[str, dict[str, float]] = defaultdict(dict)
    for (operation, parser), bucket in totals.items():
        per_operation[operation][parser] = (bucket["weighted_us"] / bucket["urls"]) if bucket["urls"] else 0.0

    rows = []
    for operation, per_parser in per_operation.items():
        fastest = min(per_parser.values()) if per_parser else 0.0

        for parser, microseconds_per_url in sorted(per_parser.items(), key=lambda item: item[1]):
            rows.append(
                {
                    "operation": operation,
                    "parser": parser,
                    "microseconds_per_url": microseconds_per_url,
                    "relative": (microseconds_per_url / fastest) if fastest else 1.0,
                }
            )

    return sorted(rows, key=lambda row: (row["operation"], row["relative"]))


def distribution_rows(results: list[dict]) -> list[dict]:
    """
    Per-URL latency distribution -- percentiles plus accepted/rejected
    split -- for every result that has one. Kept per (parser, dataset,
    operation) rather than aggregated: a p99 averaged across wildly
    different URL corpora (pathological vs. random-strings) would be
    meaningless.
    """
    rows = []

    for result in results:
        distribution = result.get("distribution")
        if not distribution:
            continue

        overall = distribution.get("overall")
        if not overall:
            continue

        accepted = distribution.get("accepted")
        rejected = distribution.get("rejected")

        rows.append(
            {
                "parser": result["parser"],
                "dataset": result["dataset"],
                "operation": result["operation"],
                "count": overall["count"],
                "mean_us": overall["mean_us"],
                "p50_us": overall["p50_us"],
                "p95_us": overall["p95_us"],
                "p99_us": overall["p99_us"],
                "max_us": overall["max_us"],
                "accepted_mean_us": accepted["mean_us"] if accepted else None,
                "rejected_mean_us": rejected["mean_us"] if rejected else None,
                "mean_url_bytes": distribution.get("mean_url_bytes"),
                "microseconds_per_byte": distribution.get("microseconds_per_byte"),
            }
        )

    return rows


def error_summary_rows(results: list[dict]) -> list[dict]:
    """Same shape as the console's ERROR SUMMARY: parser/operation/type/count."""
    counter: dict[tuple[str, str, str], int] = defaultdict(int)

    for result in results:
        for error_type, count in result["errors"]["by_type"].items():
            counter[(result["parser"], result["operation"], error_type)] += count

    return [
        {"parser": parser, "operation": operation, "error_type": error_type, "count": count}
        for (parser, operation, error_type), count in sorted(counter.items())
    ]


def top_error_types(results: list[dict], *, limit: int = 10) -> list[tuple[str, int]]:
    counter: dict[str, int] = defaultdict(int)

    for result in results:
        for error_type, count in result["errors"]["by_type"].items():
            counter[error_type] += count

    return sorted(counter.items(), key=lambda item: item[1], reverse=True)[:limit]


def grouped_by_operation(results: list[dict], metric: str) -> dict[str, dict]:
    """
    Reshape results into: {operation: {"datasets": [...], "series": {parser: [values]}}}

    One entry per (dataset, parser) pair, aligned by dataset index so Chart.js
    can render a grouped bar per operation with one bar per parser -- raw
    values plotted side by side, nothing derived.
    """
    by_operation: dict[str, dict[tuple[str, str], float]] = defaultdict(dict)
    datasets_by_operation: dict[str, list[str]] = defaultdict(list)
    parsers_seen: set[str] = set()

    for result in results:
        operation = result["operation"]
        dataset = result["dataset"]
        parser = result["parser"]
        parsers_seen.add(parser)

        if dataset not in datasets_by_operation[operation]:
            datasets_by_operation[operation].append(dataset)

        by_operation[operation][(dataset, parser)] = result[metric]

    parsers = sorted(parsers_seen)
    shaped: dict[str, dict] = {}

    for operation, values in by_operation.items():
        dataset_names = sorted(datasets_by_operation[operation])
        series = {
            parser: [values.get((dataset, parser)) for dataset in dataset_names]
            for parser in parsers
        }
        shaped[operation] = {"datasets": dataset_names, "series": series}

    return shaped


def memory_summary(results: list[dict]) -> list[dict]:
    """
    Worst-case peak / average bytes-per-URL / average object count, per
    parser+operation, across every dataset. Mirrors the console summary in
    benchmark_suite._print_memory_summary().
    """
    totals: dict[tuple[str, str], dict[str, list[float]]] = {}

    for result in results:
        memory = result.get("memory")
        if not memory:
            continue

        key = (result["parser"], result["operation"])
        bucket = totals.setdefault(key, {"peak": [], "bytes_per_url": [], "objects": []})
        bucket["peak"].append(memory["peak_bytes"])
        bucket["bytes_per_url"].append(memory["bytes_per_url"])
        bucket["objects"].append(memory["object_count"])

    rows = []
    for (parser, operation), bucket in totals.items():
        rows.append(
            {
                "parser": parser,
                "operation": operation,
                "peak_bytes": max(bucket["peak"]),
                "bytes_per_url": sum(bucket["bytes_per_url"]) / len(bucket["bytes_per_url"]),
                "object_count": sum(bucket["objects"]) / len(bucket["objects"]),
            }
        )

    return sorted(rows, key=lambda row: (row["parser"], row["operation"]))


def cache_summary(results: list[dict]) -> list[dict]:
    """
    Sum cache hit/miss deltas across every result, per parser and cache.

    Only parsers whose adapter exposes a cache_info() hook carry a
    cache_delta at all (urlps currently; None for the rest), so this is
    naturally empty for a run with no such parser.
    """
    totals: dict[tuple[str, str], dict] = {}

    for result in results:
        cache_delta = result.get("cache_delta")
        if not cache_delta:
            continue

        for category, caches in cache_delta.items():
            for cache_name, stats in caches.items():
                key = (result["parser"], f"{category}.{cache_name}")
                bucket = totals.setdefault(key, {"hits": 0, "misses": 0, "maxsize": stats.get("maxsize")})
                bucket["hits"] += stats.get("hits", 0)
                bucket["misses"] += stats.get("misses", 0)

    rows = []
    for (parser, cache_name), bucket in totals.items():
        total = bucket["hits"] + bucket["misses"]
        rows.append(
            {
                "parser": parser,
                "cache": cache_name,
                "hits": bucket["hits"],
                "misses": bucket["misses"],
                "hit_rate": (bucket["hits"] / total * 100.0) if total else None,
                "maxsize": bucket["maxsize"],
            }
        )

    return sorted(rows, key=lambda row: (row["parser"], row["cache"]))


# ============================================================================
# Security
#
# The "malicious" dataset is the hand-written adversarial URL corpus (SSRF,
# path traversal, homograph spoofing, etc. -- see url_cases/malicious.py).
# For that dataset specifically, a *rejection* (the parser raising rather
# than returning a value) is the good outcome, the inverse of every other
# dataset's success/failure framing -- so this is kept as its own section
# rather than folded into the generic error/summary aggregations.
# ============================================================================

def security_summary_rows(results: list[dict], *, dataset: str = "malicious") -> list[dict]:
    """Per parser: how many malicious URLs were rejected vs. silently accepted."""
    totals: dict[str, dict[str, int]] = {}

    for result in results:
        if result["dataset"] != dataset:
            continue

        bucket = totals.setdefault(result["parser"], {"urls": 0, "rejected": 0, "accepted": 0})
        bucket["urls"] += result["urls"]
        bucket["rejected"] += result["failed"]
        bucket["accepted"] += result["successful"]

    rows = []
    for parser, bucket in totals.items():
        urls = bucket["urls"]
        rows.append(
            {
                "parser": parser,
                "urls": urls,
                "rejected": bucket["rejected"],
                "accepted": bucket["accepted"],
                "rejection_rate": (bucket["rejected"] / urls * 100.0) if urls else 0.0,
            }
        )

    return sorted(rows, key=lambda row: row["rejection_rate"], reverse=True)


def security_error_rows(results: list[dict], *, dataset: str = "malicious") -> list[dict]:
    """Which specific validation errors each parser raised against the malicious corpus."""
    counter: dict[tuple[str, str], int] = defaultdict(int)

    for result in results:
        if result["dataset"] != dataset:
            continue

        for error_type, count in result["errors"]["by_type"].items():
            counter[(result["parser"], error_type)] += count

    return [
        {"parser": parser, "error_type": error_type, "count": count}
        for (parser, error_type), count in sorted(counter.items())
    ]


# ============================================================================
# Expectation accuracy
#
# Whether each parser's accept/reject verdict matched a URL's *known*
# expected outcome (see EXPECTATION_* in url_cases/_models.py), rather than
# the older, cruder "any rejection on the malicious dataset is good" proxy.
# Most of the malicious corpus is syntactically valid URLs with dangerous
# semantics (SSRF targets, credential smuggling, ...) -- accepting one is
# correct behavior for a plain parser; only adapters tagged "security" are
# scored against that "unsafe" bucket. See benchmark_suite.py's
# _measure_expectation_accuracy() for where this data actually comes from.
# ============================================================================

def expectation_accuracy_rows(results: list[dict]) -> list[dict]:
    """Per parser, per expectation bucket: summed across every dataset+operation."""
    totals: dict[tuple[str, str], dict[str, int]] = {}

    for result in results:
        accuracy = result.get("expectation_accuracy")
        if not accuracy:
            continue

        for expectation, bucket in accuracy.items():
            key = (result["parser"], expectation)
            running = totals.setdefault(key, {"total": 0, "correct": 0, "incorrect": 0})
            running["total"] += bucket["total"]
            running["correct"] += bucket["correct"]
            running["incorrect"] += bucket["incorrect"]

    rows = []
    for (parser, expectation), bucket in totals.items():
        total = bucket["total"]
        rows.append(
            {
                "parser": parser,
                "expectation": expectation,
                "total": total,
                "correct": bucket["correct"],
                "incorrect": bucket["incorrect"],
                "accuracy_pct": (bucket["correct"] / total * 100.0) if total else 0.0,
            }
        )

    return sorted(rows, key=lambda row: (row["expectation"], row["parser"]))


def expectation_accuracy_detail_rows(results: list[dict]) -> list[dict]:
    """One row per parser/dataset/operation/expectation-bucket combination."""
    rows = []

    for result in results:
        accuracy = result.get("expectation_accuracy")
        if not accuracy:
            continue

        for expectation, bucket in accuracy.items():
            total = bucket["total"]
            rows.append(
                {
                    "parser": result["parser"],
                    "dataset": result["dataset"],
                    "operation": result["operation"],
                    "expectation": expectation,
                    "total": total,
                    "correct": bucket["correct"],
                    "incorrect": bucket["incorrect"],
                    "accuracy_pct": (bucket["correct"] / total * 100.0) if total else 0.0,
                }
            )

    return sorted(rows, key=lambda row: (row["parser"], row["dataset"], row["operation"], row["expectation"]))
