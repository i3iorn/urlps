"""
Core benchmark engine for URL parsers.

The engine measures both performance and behavior.

Every parser operation is isolated per URL. A parser throwing ValueError,
TypeError, AttributeError, etc. does not terminate the benchmark.
"""

from __future__ import annotations

import cProfile
import json
import pstats
import statistics
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from .adapters._models import OperationError, ParserAdapter
from .url_cases import URLDataset


# ============================================================================
# Result structures
# ============================================================================

@dataclass
class ErrorStats:
    count: int = 0
    by_type: dict[str, int] = field(default_factory=dict)
    examples: list[dict[str, Any]] = field(default_factory=list)

    def record(
        self,
        error: OperationError,
        *,
        url: str,
        max_examples: int = 10,
    ) -> None:
        self.count += 1

        self.by_type[error.exception_type] = (
            self.by_type.get(error.exception_type, 0) + 1
        )

        if len(self.examples) < max_examples:
            self.examples.append(
                {
                    "url": url,
                    **error.as_dict(),
                }
            )


@dataclass
class BenchmarkResult:
    parser: str
    dataset: str
    operation: str

    urls: int
    successful: int
    failed: int

    elapsed_seconds: float
    parses_per_second: float
    microseconds_per_url: float

    errors: ErrorStats = field(default_factory=ErrorStats)

    # Per-URL latency distribution (percentiles, accepted vs. rejected split,
    # per-byte throughput). Measured in a dedicated single pass -- see
    # _measure_latency_distribution() -- so the timer overhead of timing
    # every URL individually never inflates elapsed_seconds/
    # microseconds_per_url above, which stay a pure batch wall-clock number.
    distribution: dict[str, Any] = field(default_factory=dict)

    # Cache hit/miss delta over this benchmark, for parsers whose adapter
    # exposes a cache_info() hook (currently just urlps). None when the
    # parser has no such introspection.
    cache_delta: dict[str, Any] | None = None

    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        if self.urls == 0:
            return 0.0

        return self.successful / self.urls * 100.0

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["success_rate"] = self.success_rate
        return data


# ============================================================================
# Safe operations
# ============================================================================

def _safe_parse(
    adapter: ParserAdapter,
    url: str,
) -> tuple[Any | None, OperationError | None]:
    try:
        return adapter.parse(url), None
    except Exception as exc:
        return None, OperationError(
            stage="parse",
            exception_type=type(exc).__name__,
            message=str(exc),
        )


def _execute_single(
    adapter: ParserAdapter,
    url: str,
    operation: str,
) -> tuple[bool, list[OperationError]]:
    """
    Execute one operation on one URL.

    Returns (success, errors). `errors` may contain more than one entry for
    "components" (each failed component is recorded independently) and is
    otherwise 0 or 1 entries.
    """
    parsed, parse_error = _safe_parse(adapter, url)

    if parse_error is not None:
        return False, [parse_error]

    try:
        if operation == "parse":
            return True, []

        elif operation == "components":
            component_result = adapter.components(parsed)
            if component_result.errors:
                return False, list(component_result.errors)
            return True, []

        elif operation == "query":
            query_result = adapter.query(parsed)
            if not query_result.ok:
                return False, ([query_result.error] if query_result.error is not None else [])
            return True, []

        elif operation == "reconstruct":
            _, error = adapter.reconstruct(parsed)
            if error is not None:
                return False, [error]
            return True, []

        else:
            raise ValueError(f"Unknown benchmark operation: {operation}")

    except Exception as exc:
        # Last line of defence. No parser implementation should be able to
        # kill the benchmark runner.
        return False, [
            OperationError(
                stage=operation,
                exception_type=type(exc).__name__,
                message=str(exc),
            )
        ]


def _run_operation(
    adapter: ParserAdapter,
    urls: list[str],
    operation: str,
) -> tuple[
    int,
    int,
    float,
    ErrorStats,
]:
    """
    Execute one operation across a URL collection, timed as a single batch.

    This is the "official" timing path used for elapsed_seconds /
    microseconds_per_url: one perf_counter() pair around the whole batch,
    so per-call timer overhead never enters the headline throughput number.

    Returns:
        successful
        failed
        elapsed
        error stats
    """

    successful = 0
    failed = 0
    errors = ErrorStats()

    start = time.perf_counter()

    for url in urls:
        ok, url_errors = _execute_single(adapter, url, operation)

        if ok:
            successful += 1
        else:
            failed += 1
            for error in url_errors:
                errors.record(error, url=url)

    elapsed = time.perf_counter() - start

    return successful, failed, elapsed, errors


# ============================================================================
# Timing
# ============================================================================

def benchmark_operation(
    adapter: ParserAdapter,
    dataset: URLDataset,
    operation: str,
    *,
    repeats: int = 5,
    warmups: int = 1,
    measure_distribution: bool = True,
) -> BenchmarkResult:
    """
    Benchmark an operation.

    Errors are collected on every invocation.
    """

    urls = dataset.urls

    # Warmups are deliberately ignored in statistics.
    for _ in range(warmups):
        _run_operation(adapter, urls, operation)

    timings: list[float] = []

    final_successful = 0
    final_failed = 0
    final_errors = ErrorStats()

    for _ in range(repeats):
        successful, failed, elapsed, errors = _run_operation(
            adapter,
            urls,
            operation,
        )

        timings.append(elapsed)

        # Keep the final run's behavioral statistics.
        final_successful = successful
        final_failed = failed
        final_errors = errors

    elapsed = statistics.median(timings)

    urls_count = len(urls)

    if elapsed > 0:
        parses_per_second = urls_count / elapsed
        microseconds_per_url = elapsed / urls_count * 1_000_000
    else:
        parses_per_second = float("inf")
        microseconds_per_url = 0.0

    distribution: dict[str, Any] = {}
    cache_delta: dict[str, Any] | None = None

    if measure_distribution:
        cache_before = adapter.cache_info() if adapter.cache_info is not None else None

        distribution = _measure_latency_distribution(adapter, urls, operation)

        if adapter.cache_info is not None:
            cache_after = adapter.cache_info()
            cache_delta = _cache_delta(cache_before, cache_after)

    return BenchmarkResult(
        parser=adapter.name,
        dataset=dataset.name,
        operation=operation,
        urls=urls_count,
        successful=final_successful,
        failed=final_failed,
        elapsed_seconds=elapsed,
        parses_per_second=parses_per_second,
        microseconds_per_url=microseconds_per_url,
        errors=final_errors,
        distribution=distribution,
        cache_delta=cache_delta,
        extra={
            "all_timings_seconds": timings,
            "min_seconds": min(timings),
            "max_seconds": max(timings),
            "mean_seconds": statistics.mean(timings),
        },
    )


# ============================================================================
# Latency distribution: percentiles + accepted/rejected split + per-byte
# throughput
# ============================================================================

def _percentile(sorted_values: list[float], pct: float) -> float:
    """Nearest-rank percentile. `sorted_values` must already be sorted."""
    if not sorted_values:
        return 0.0

    rank = max(
        0,
        min(len(sorted_values) - 1, int(round(pct / 100 * (len(sorted_values) - 1)))),
    )
    return sorted_values[rank]


def _summarize_latencies(values_us: list[float]) -> dict[str, Any] | None:
    if not values_us:
        return None

    values_us = sorted(values_us)

    return {
        "count": len(values_us),
        "mean_us": statistics.mean(values_us),
        "p50_us": _percentile(values_us, 50),
        "p95_us": _percentile(values_us, 95),
        "p99_us": _percentile(values_us, 99),
        "max_us": values_us[-1],
    }


def _measure_latency_distribution(
    adapter: ParserAdapter,
    urls: list[str],
    operation: str,
) -> dict[str, Any]:
    """
    Time every URL individually to get a per-call latency distribution.

    This is a single dedicated pass, separate from the repeated-batch timing
    in _run_operation(): timing each call individually adds real per-call
    overhead (most visible for very fast operations), so this is used only
    for percentiles / accepted-vs-rejected latency / per-byte throughput,
    never for the headline elapsed_seconds/microseconds_per_url numbers.
    """
    all_us: list[float] = []
    accepted_us: list[float] = []
    rejected_us: list[float] = []
    total_bytes = 0

    for url in urls:
        start = time.perf_counter()
        ok, _errors = _execute_single(adapter, url, operation)
        elapsed_us = (time.perf_counter() - start) * 1_000_000

        all_us.append(elapsed_us)
        total_bytes += len(url)
        (accepted_us if ok else rejected_us).append(elapsed_us)

    total_us = sum(all_us)

    return {
        "overall": _summarize_latencies(all_us),
        "accepted": _summarize_latencies(accepted_us),
        "rejected": _summarize_latencies(rejected_us),
        "mean_url_bytes": (total_bytes / len(urls)) if urls else 0.0,
        "microseconds_per_byte": (total_us / total_bytes) if total_bytes else None,
    }


# ============================================================================
# Cache hit-rate snapshot
# ============================================================================

def _cache_delta(before: dict[str, Any] | None, after: dict[str, Any] | None) -> dict[str, Any]:
    """
    Diff two get_cache_info()-shaped snapshots into a per-cache hit/miss
    delta for just this benchmark run, rather than raw cumulative counters
    that would also include everything before the run started.
    """
    before = before or {}
    after = after or {}

    delta: dict[str, Any] = {}

    for category, caches in after.items():
        before_caches = before.get(category, {})
        category_delta: dict[str, Any] = {}

        for cache_name, stats in caches.items():
            before_stats = before_caches.get(cache_name, {})

            hits = stats.get("hits", 0) - before_stats.get("hits", 0)
            misses = stats.get("misses", 0) - before_stats.get("misses", 0)
            total = hits + misses

            category_delta[cache_name] = {
                "hits": hits,
                "misses": misses,
                "hit_rate_pct": (hits / total * 100.0) if total else None,
                "maxsize": stats.get("maxsize"),
                "currsize_after": stats.get("currsize"),
            }

        delta[category] = category_delta

    return delta


# ============================================================================
# Repeated parsing benchmark
# ============================================================================

def benchmark_repeated_parse(
    adapter: ParserAdapter,
    dataset: URLDataset,
    *,
    parse_repeats: int = 3,
    repeats: int = 5,
    warmups: int = 1,
) -> BenchmarkResult:
    urls = dataset.urls

    def work() -> tuple[int, int, ErrorStats]:
        successful = 0
        failed = 0
        errors = ErrorStats()

        for _ in range(parse_repeats):
            for url in urls:
                _, error = _safe_parse(adapter, url)

                if error is not None:
                    failed += 1
                    errors.record(error, url=url)
                else:
                    successful += 1

        return successful, failed, errors

    for _ in range(warmups):
        work()

    timings: list[float] = []
    final_successful = 0
    final_failed = 0
    final_errors = ErrorStats()

    for _ in range(repeats):
        start = time.perf_counter()

        successful, failed, errors = work()

        elapsed = time.perf_counter() - start

        timings.append(elapsed)
        final_successful = successful
        final_failed = failed
        final_errors = errors

    elapsed = statistics.median(timings)
    total_urls = len(urls) * parse_repeats

    return BenchmarkResult(
        parser=adapter.name,
        dataset=dataset.name,
        operation=f"repeated-parse-{parse_repeats}x",
        urls=total_urls,
        successful=final_successful,
        failed=final_failed,
        elapsed_seconds=elapsed,
        parses_per_second=(
            total_urls / elapsed if elapsed > 0 else float("inf")
        ),
        microseconds_per_url=(
            elapsed / total_urls * 1_000_000
            if total_urls
            else 0
        ),
        errors=final_errors,
        extra={
            "parse_repeats": parse_repeats,
            "all_timings_seconds": timings,
        },
    )


# ============================================================================
# Concurrency benchmark
# ============================================================================

@dataclass
class ConcurrencyResult:
    parser: str
    dataset: str
    operation: str

    # Aligned lists: levels[i] workers achieved urls_per_second[i].
    worker_counts: list[int]
    urls_per_second: list[float]
    elapsed_seconds: list[float]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def benchmark_concurrency(
    adapter: ParserAdapter,
    dataset: URLDataset,
    operation: str = "parse",
    *,
    worker_counts: tuple[int, ...] = (1, 2, 4, 8),
    repeats: int = 3,
) -> ConcurrencyResult:
    """
    Measure throughput at increasing thread counts.

    CPython's GIL means pure-Python parsing work does not parallelize the
    way I/O-bound work would -- the point of this benchmark is not to prove
    otherwise, but to surface whether shared state (lru_cache locks, the
    audit manager, etc.) becomes a contention bottleneck under concurrent
    load, which single-threaded benchmarking can never show.
    """
    urls = dataset.urls

    urls_per_second: list[float] = []
    elapsed_list: list[float] = []

    for workers in worker_counts:
        timings: list[float] = []

        for _ in range(repeats):
            start = time.perf_counter()

            with ThreadPoolExecutor(max_workers=workers) as pool:
                list(pool.map(lambda url: _execute_single(adapter, url, operation), urls))

            timings.append(time.perf_counter() - start)

        median_elapsed = statistics.median(timings)
        elapsed_list.append(median_elapsed)
        urls_per_second.append(len(urls) / median_elapsed if median_elapsed > 0 else float("inf"))

    return ConcurrencyResult(
        parser=adapter.name,
        dataset=dataset.name,
        operation=operation,
        worker_counts=list(worker_counts),
        urls_per_second=urls_per_second,
        elapsed_seconds=elapsed_list,
    )


def save_concurrency_results(
    results: list[ConcurrencyResult],
    path: str | Path,
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "results": [result.as_dict() for result in results],
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def print_concurrency_summary(results: list[ConcurrencyResult]) -> None:
    print()
    print("=" * 90)
    print("CONCURRENCY SUMMARY")
    print("=" * 90)

    header = f"{'Parser':<12}{'Dataset':<18}{'Operation':<14}{'Workers':>10}{'URLs/sec':>16}"
    print(header)
    print("-" * 90)

    for result in results:
        for workers, ups in zip(result.worker_counts, result.urls_per_second):
            print(
                f"{result.parser:<12}"
                f"{result.dataset:<18}"
                f"{result.operation:<14}"
                f"{workers:>10}"
                f"{ups:>16,.1f}"
            )

    print("=" * 90)


# ============================================================================
# Full suite
# ============================================================================

DEFAULT_OPERATIONS = [
    "parse",
    "components",
    "query",
    "reconstruct",
]


def run_suite(
    adapters: list[ParserAdapter],
    datasets: list[URLDataset],
    *,
    operations: list[str] | None = None,
    repeats: int = 5,
    warmups: int = 1,
    repeated_parse: int = 3,
) -> list[BenchmarkResult]:
    if operations is None:
        operations = DEFAULT_OPERATIONS

    results: list[BenchmarkResult] = []

    for adapter in adapters:
        print()
        print("=" * 80)
        print(f"PARSER: {adapter.name}")
        print("=" * 80)

        for dataset in datasets:
            print(f"\nDataset: {dataset.name} ({dataset.size} URLs)")

            for operation in operations:
                print(
                    f"  {operation:<16}",
                    end="",
                    flush=True,
                )

                result = benchmark_operation(
                    adapter,
                    dataset,
                    operation,
                    repeats=repeats,
                    warmups=warmups,
                )

                results.append(result)

                overall = result.distribution.get("overall") if result.distribution else None
                p95_text = f"  p95={overall['p95_us']:.3f}us" if overall else ""

                print(
                    f"{result.elapsed_seconds * 1000:10.3f} ms  "
                    f"{result.microseconds_per_url:8.3f} us/url"
                    f"{p95_text}  "
                    f"ok={result.successful:<6} "
                    f"fail={result.failed:<6}"
                )

                if result.errors.count:
                    print(
                        f"    errors: {result.errors.count} "
                        f"{dict(result.errors.by_type)}"
                    )

            if repeated_parse > 1:
                result = benchmark_repeated_parse(
                    adapter,
                    dataset,
                    parse_repeats=repeated_parse,
                    repeats=repeats,
                    warmups=warmups,
                )

                results.append(result)

                print(
                    f"  {'repeated parse':<16}"
                    f"{result.elapsed_seconds * 1000:10.3f} ms  "
                    f"{result.microseconds_per_url:8.3f} us/url  "
                    f"ok={result.successful:<6} "
                    f"fail={result.failed:<6}"
                )

    return results


# ============================================================================
# JSON output
# ============================================================================

def save_results(
    results: list[BenchmarkResult],
    path: str | Path,
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "results": [result.as_dict() for result in results],
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    path.write_text(
        json.dumps(
            payload,
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )


# ============================================================================
# Console summary
# ============================================================================

def print_summary(results: list[BenchmarkResult]) -> None:
    print()
    print("=" * 130)
    print("BENCHMARK SUMMARY")
    print("=" * 130)

    header = (
        f"{'Parser':<12}"
        f"{'Dataset':<18}"
        f"{'Operation':<22}"
        f"{'ms':>12}"
        f"{'us/url':>12}"
        f"{'p95 us':>12}"
        f"{'OK':>10}"
        f"{'FAIL':>10}"
    )

    print(header)
    print("-" * 130)

    for result in results:
        overall = result.distribution.get("overall") if result.distribution else None
        p95_text = f"{overall['p95_us']:>12.3f}" if overall else f"{'n/a':>12}"

        print(
            f"{result.parser:<12}"
            f"{result.dataset:<18}"
            f"{result.operation:<22}"
            f"{result.elapsed_seconds * 1000:>12.3f}"
            f"{result.microseconds_per_url:>12.3f}"
            f"{p95_text}"
            f"{result.successful:>10}"
            f"{result.failed:>10}"
        )

    print("=" * 130)

    print("\nERROR SUMMARY")

    error_counter: Counter[tuple[str, str, str]] = Counter()

    for result in results:
        for error_type, count in result.errors.by_type.items():
            error_counter[
                (
                    result.parser,
                    result.operation,
                    error_type,
                )
            ] += count

    if not error_counter:
        print("No errors recorded.")
    else:
        for (parser, operation, error_type), count in sorted(
            error_counter.items()
        ):
            print(
                f"  {parser:<12} "
                f"{operation:<20} "
                f"{error_type:<30} "
                f"{count}"
            )

    _print_cache_summary(results)


def _print_cache_summary(results: list[BenchmarkResult]) -> None:
    with_cache = [r for r in results if r.cache_delta]
    if not with_cache:
        return

    print("\nCACHE HIT RATES (this run, by parser)")

    totals: dict[str, dict[str, tuple[int, int]]] = {}

    for result in with_cache:
        for category, caches in result.cache_delta.items():
            for cache_name, stats in caches.items():
                key = f"{result.parser}:{category}.{cache_name}"
                hits, misses = totals.get(key, (0, 0))
                totals[key] = (hits + stats["hits"], misses + stats["misses"])

    for key, (hits, misses) in sorted(totals.items()):
        total = hits + misses
        rate = f"{hits / total * 100:.1f}%" if total else "n/a"
        print(f"  {key:<45} hits={hits:<10,} misses={misses:<10,} hit_rate={rate}")


# ============================================================================
# cProfile
# ============================================================================

def profile_parser(
    adapter: ParserAdapter,
    dataset: URLDataset,
    *,
    operation: str = "parse",
    repeats: int = 10,
    profile_path: str | Path = "performance/profile_results.prof",
    text_path: str | Path = "performance/profile_results.txt",
) -> None:
    """
    Profile a parser while retaining the same exception safety as the suite.
    """

    profile_path = Path(profile_path)
    text_path = Path(text_path)

    profile_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.parent.mkdir(parents=True, exist_ok=True)

    profiler = cProfile.Profile()

    print()
    print("=" * 80)
    print(f"cProfile: {adapter.name} / {dataset.name} / {operation}")
    print("=" * 80)

    profiler.enable()

    try:
        for _ in range(repeats):
            _run_operation(
                adapter,
                dataset.urls,
                operation,
            )
    finally:
        profiler.disable()

    profiler.dump_stats(str(profile_path))

    stats = pstats.Stats(profiler)
    stats.sort_stats("cumulative")

    with text_path.open("w", encoding="utf-8") as fh:
        fh.write(
            f"Parser: {adapter.name}\n"
            f"Dataset: {dataset.name}\n"
            f"Operation: {operation}\n"
            f"Repeats: {repeats}\n\n"
        )

        stats.stream = fh
        stats.print_stats(100)

    print(f"Raw profile: {profile_path}")
    print(f"Text profile: {text_path}")
