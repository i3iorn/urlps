"""
Core benchmark engine for URL parsers.

The engine measures both performance and behavior.

Every parser operation is isolated per URL. A parser throwing ValueError,
TypeError, AttributeError, etc. does not terminate the benchmark.
"""

from __future__ import annotations

import cProfile
import gc
import pstats
import statistics
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from .tuner import TunableDataset
from .adapters._models import OperationError, ParserAdapter
from .url_cases import (
    EXPECTATION_AMBIGUOUS,
    EXPECTATION_INVALID,
    EXPECTATION_UNKNOWN,
    EXPECTATION_UNSAFE,
    EXPECTATION_VALID,
    MODIFY_OPERATIONS,
    URLDataset,
    generate_complex_urls,
    generate_encoded_urls,
    generate_invalid_port_urls,
    generate_ipv6_urls,
    generate_long_query_urls,
    generate_mixed_urls,
    generate_random_strings,
    generate_relative_urls,
    generate_simple_urls,
)

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

    # Memory footprint of a single pass over the dataset -- see
    # _measure_memory() below. peak_bytes/object_count are tracemalloc
    # numbers, so they reflect Python-level allocations only (not e.g. C
    # extension heap usage that tracemalloc doesn't instrument).
    memory: dict[str, Any] | None = None

    # Accuracy against each URL's known expected outcome (see
    # _measure_expectation_accuracy() below and EXPECTATION_* in
    # url_cases/_models.py) -- {expectation: {"total", "correct",
    # "incorrect"}}, one entry per expectation bucket this dataset actually
    # carries. None when the dataset has no expectation data at all (most
    # generated corpora) or nothing was scoreable for this adapter.
    expectation_accuracy: dict[str, dict[str, int]] | None = None

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
    if adapter.parse is None:
        # Validation-only/normalization-only adapters (validators,
        # urlpolice, url_normalize, ...) have no parsed-object step at all;
        # run_suite() only ever routes them to "validate"/"normalize",
        # which don't call this. This guard is defence in depth for direct
        # callers (tests, REPL use) rather than the normal path.
        return None, OperationError(
            stage="parse",
            exception_type="NotSupportedError",
            message="parse is not supported",
        )

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
    # "validate"/"normalize" work directly on the URL string -- there's no
    # parsed-object step to run first (see ParserAdapter.validator's
    # docstring), unlike every operation below.
    if operation == "validate":
        result = adapter.validate(url)
        if not result.ok:
            return False, ([result.error] if result.error is not None else [])
        return True, []

    if operation == "normalize":
        normalize_result = adapter.normalize(url)
        if not normalize_result.ok:
            return False, ([normalize_result.error] if normalize_result.error is not None else [])
        return True, []

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

        elif operation in MODIFY_OPERATIONS:
            component = operation[len("modify_"):]
            _, error = adapter.modify(parsed, component)
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
    measure_memory: bool = True,
    measure_expectations: bool = True,
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

    memory: dict[str, Any] | None = None

    if measure_memory:
        memory = _measure_memory(adapter, urls, operation)

    expectation_accuracy: dict[str, dict[str, int]] | None = None

    if measure_expectations:
        expectation_accuracy = _measure_expectation_accuracy(
            adapter, urls, dataset.expectations, operation
        )

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
        memory=memory,
        expectation_accuracy=expectation_accuracy,
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
# Memory: peak allocated, bytes/URL, object count
# ============================================================================

def _measure_memory(
    adapter: ParserAdapter,
    urls: list[str],
    operation: str,
) -> dict[str, Any]:
    """
    Measure the memory footprint of a single pass over `urls`, via
    tracemalloc.

    A dedicated pass, like _measure_latency_distribution() -- tracemalloc's
    per-allocation bookkeeping has real overhead, so this never feeds into
    the headline elapsed_seconds/microseconds_per_url numbers.

    - peak_bytes: the high-water mark of traced Python allocations during
      the pass (tracemalloc.get_traced_memory()'s peak).
    - object_count: number of distinct traced allocations still live at the
      end of the pass -- i.e. what's actually retained (results, caches),
      not the full churn of every temporary created along the way.
    - bytes_per_url: peak_bytes / len(urls), the closest single number to
      "memory cost per URL" without assuming allocations are independent
      across URLs.

    gc.collect() runs first so the baseline doesn't include garbage left
    over from prior benchmarks/warmups.
    """

    gc.collect()

    tracemalloc.start()

    try:
        _run_operation(adapter, urls, operation)

        snapshot = tracemalloc.take_snapshot()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    object_count = sum(stat.count for stat in snapshot.statistics("filename"))

    urls_count = len(urls)

    return {
        "peak_bytes": peak,
        "bytes_per_url": (peak / urls_count) if urls_count else 0.0,
        "object_count": object_count,
    }


# ============================================================================
# Expectation accuracy: does accept/reject match the URL's known-correct
# outcome (see EXPECTATION_* in url_cases/_models.py)?
# ============================================================================

def _measure_expectation_accuracy(
    adapter: ParserAdapter,
    urls: list[str],
    expectations: tuple[str, ...],
    operation: str,
) -> dict[str, dict[str, int]] | None:
    """
    A dedicated pass, like _measure_latency_distribution()/_measure_memory()
    -- re-running each URL here rather than piggybacking on the timed batch
    in _run_operation() keeps this measurement's cost off the headline
    elapsed_seconds/microseconds_per_url numbers.

    For each URL with a known expectation:

        EXPECTATION_VALID   -- correct if the operation succeeded
        EXPECTATION_INVALID -- correct if the operation failed (rejected)
        EXPECTATION_UNSAFE  -- syntactically valid, semantically dangerous.
                                Only scored for adapters tagged "security" --
                                accepting it is not a bug for a plain parser
                                that was never asked to judge safety.
        EXPECTATION_AMBIGUOUS / EXPECTATION_UNKNOWN -- never scored (no
                                single right answer, or no data at all).

    Returns None if nothing was scoreable for this adapter/dataset pair
    (e.g. every URL is EXPECTATION_UNKNOWN, or every scoreable one is
    EXPECTATION_UNSAFE and this adapter isn't tagged "security").
    """
    is_security_adapter = "security" in adapter.tags

    buckets: dict[str, dict[str, int]] = {}

    for url, expectation in zip(urls, expectations):
        if expectation in (EXPECTATION_UNKNOWN, EXPECTATION_AMBIGUOUS):
            continue

        if expectation == EXPECTATION_UNSAFE and not is_security_adapter:
            continue

        ok, _errors = _execute_single(adapter, url, operation)

        bucket = buckets.setdefault(expectation, {"total": 0, "correct": 0, "incorrect": 0})
        bucket["total"] += 1

        # VALID expects acceptance; INVALID/UNSAFE both expect rejection.
        expected_ok = expectation == EXPECTATION_VALID

        if ok == expected_ok:
            bucket["correct"] += 1
        else:
            bucket["incorrect"] += 1

    return buckets or None


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


# name -> (generator, starting n, expectation). One entry per tunable
# dataset -- unlike the old calibrator, each is sized independently rather
# than five sharing one "edge" knob, since each now finds its own size
# live. `mixed`/`random-strings` are left unannotated (None): both
# deliberately blend valid/invalid/unparseable input, so there's no single
# right answer to check the whole dataset against.
TUNABLE_DATASET_SPECS: list[tuple[str, Callable[[int], list[str]], int, str | None]] = [
    ("simple", lambda n: generate_simple_urls(n, seed=0), 1000, EXPECTATION_VALID),
    ("complex", lambda n: generate_complex_urls(n, seed=1), 1000, EXPECTATION_VALID),
    ("ipv6", lambda n: generate_ipv6_urls(n, seed=2), 1000, EXPECTATION_VALID),
    ("invalid-port", lambda n: generate_invalid_port_urls(n, seed=3), 1000, EXPECTATION_INVALID),
    ("long-query", lambda n: generate_long_query_urls(n, seed=4), 500, EXPECTATION_VALID),
    ("encoded", lambda n: generate_encoded_urls(n, seed=5), 1000, EXPECTATION_VALID),
    ("relative", lambda n: generate_relative_urls(n, seed=6), 1000, EXPECTATION_VALID),
    ("mixed", lambda n: generate_mixed_urls(n, seed=42), 1000, None),
    ("random-strings", lambda n: generate_random_strings(n, seed=7), 1000, None),
]


def build_tunable_datasets(
    *,
    starting_sizes: dict[str, int] | None = None,
) -> list[TunableDataset]:
    """
    Build the self-adjusting datasets, optionally overriding a starting n
    (final sizes still drift from there as the suite runs).
    """
    starting_sizes = starting_sizes or {}

    return [
        TunableDataset(name, make_urls, starting_sizes.get(name, default_n), expectation=expectation)
        for name, make_urls, default_n, expectation in TUNABLE_DATASET_SPECS
    ]


# ============================================================================
# Full suite
# ============================================================================

DEFAULT_OPERATIONS = [
    "parse",
    "components",
    "query",
    "reconstruct",
    "modify_path",
    "modify_query",
    "modify_host",
    "modify_fragment",
    "validate",
    "normalize",
]


def count_planned_steps(
    adapters: list[ParserAdapter],
    datasets: list[URLDataset],
    operations: list[str],
    *,
    repeated_parse: int = 1,
) -> int:
    """
    How many (parser, dataset, operation) benchmark steps run_suite() will
    actually execute for this adapter/dataset/operation selection.

    Used by callers (the CLI's live-progress counter) that need the total
    up front, before run_suite() itself applies the same per-adapter
    "only operations this adapter actually supports" and per-dataset
    "excluded_operations"/"skip_repeated_parse" filtering.
    """
    total = 0

    for adapter in adapters:
        supported = adapter.supported_operations
        adapter_operations = [operation for operation in operations if operation in supported]

        for dataset in datasets:
            dataset_operations = [
                operation for operation in adapter_operations
                if operation not in dataset.excluded_operations
            ]

            steps = len(dataset_operations)
            if repeated_parse > 1 and adapter.parse is not None and not dataset.skip_repeated_parse:
                steps += 1

            total += steps

    return total


def run_suite(
    adapters: list[ParserAdapter],
    datasets: list[URLDataset],
    *,
    operations: list[str] | None = None,
    repeats: int = 5,
    warmups: int = 1,
    repeated_parse: int = 3,
    on_parser_start: Callable[[ParserAdapter], None] | None = None,
    on_dataset_start: Callable[[Any], None] | None = None,
    on_operation_start: Callable[[str], None] | None = None,
    on_result: Callable[[BenchmarkResult], None] | None = None,
    on_dataset_adjusted: Callable[[TunableDataset], None] | None = None,
) -> list[BenchmarkResult]:
    """
    Run the complete benchmark suite.

    The engine itself performs no console output. Optional callbacks allow
    callers such as the CLI to provide progress reporting without coupling
    the benchmark engine to presentation.
    """
    if operations is None:
        operations = DEFAULT_OPERATIONS

    results: list[BenchmarkResult] = []

    for adapter in adapters:
        if on_parser_start is not None:
            on_parser_start(adapter)

        # Not every adapter supports every operation -- a pure validator
        # has no "components" to extract, a normalizer has no "parse" at
        # all. Run only the intersection instead of recording a wall of
        # NotSupportedError entries for the rest (see
        # ParserAdapter.supported_operations).
        adapter_operations = [
            operation
            for operation in operations
            if operation in adapter.supported_operations
        ]

        for dataset in datasets:
            if on_dataset_start is not None:
                on_dataset_start(dataset)

            # Some operations are uninformative on some datasets -- e.g.
            # modify_* on the malicious corpus tests nothing about *that*
            # corpus's purpose (see URLDataset.excluded_operations).
            dataset_operations = [
                operation
                for operation in adapter_operations
                if operation not in dataset.excluded_operations
            ]

            for operation in dataset_operations:
                wall_start = time.perf_counter()

                if on_operation_start is not None:
                    on_operation_start(operation)

                result = benchmark_operation(
                    adapter,
                    dataset,
                    operation,
                    repeats=repeats,
                    warmups=warmups,
                )

                results.append(result)

                if on_result is not None:
                    on_result(result)

                wall_elapsed = (
                    time.perf_counter() - wall_start
                )

                if isinstance(dataset, TunableDataset):
                    changed = dataset.adjust(
                        wall_elapsed
                    )

                    if (
                        changed
                        and on_dataset_adjusted is not None
                    ):
                        on_dataset_adjusted(dataset)

            if repeated_parse > 1 and adapter.parse is not None and not dataset.skip_repeated_parse:
                result = benchmark_repeated_parse(
                    adapter,
                    dataset,
                    parse_repeats=repeated_parse,
                    repeats=repeats,
                    warmups=warmups,
                )

                results.append(result)

                if on_result is not None:
                    on_result(result)

    return results

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
) -> tuple[Path, Path]:
    """
    Profile a parser while retaining the same exception safety as the suite.

    Returns:
        (profile_path, text_path)
    """
    profile_path = Path(profile_path)
    text_path = Path(text_path)

    profile_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    text_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    profiler = cProfile.Profile()

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

    profiler.dump_stats(
        str(profile_path)
    )

    stats = pstats.Stats(profiler)
    stats.sort_stats("cumulative")

    with text_path.open(
        "w",
        encoding="utf-8",
    ) as fh:
        fh.write(
            f"Parser: {adapter.name}\n"
            f"Dataset: {dataset.name}\n"
            f"Operation: {operation}\n"
            f"Repeats: {repeats}\n\n"
        )

        stats.stream = fh
        stats.print_stats(100)

    return profile_path, text_path
