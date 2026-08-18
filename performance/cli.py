#!/usr/bin/env python3

"""
Single CLI entry point for the URL parser performance suite.

Usage:

    python -m performance benchmark
    python -m performance benchmark --parser urlps --pathological
    python -m performance profile --parser urlps --dataset mixed
    python -m performance report
    python -m performance concurrency --parser urlps --workers 1 2 4 8
    python -m performance compare baseline.json benchmark_results.json
    python -m performance list-parsers
    python -m performance all

Run `python -m performance <command> --help` for command-specific options.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import urlps

from .adapters import get_adapter, get_adapters
from .benchmark_suite import (
    benchmark_concurrency,
    print_concurrency_summary,
    print_summary,
    profile_parser,
    run_suite,
    save_concurrency_results,
    save_results,
)
from .performance_report import generate_html, load_results
from .url_cases import build_datasets

PERFORMANCE_DIR = Path(__file__).resolve().parent

DEFAULT_RESULTS_JSON = PERFORMANCE_DIR / "benchmark_results.json"
DEFAULT_REPORT_HTML = PERFORMANCE_DIR / "performance_report.html"
DEFAULT_PROFILE_PROF = PERFORMANCE_DIR / "profile_results.prof"
DEFAULT_PROFILE_TXT = PERFORMANCE_DIR / "profile_results.txt"
DEFAULT_CONCURRENCY_JSON = PERFORMANCE_DIR / "concurrency_results.json"

DATASET_CHOICES = [
    "simple",
    "complex",
    "pathological",
    "malicious",
    "ipv6",
    "invalid-port",
    "long-query",
    "encoded",
    "relative",
    "mixed",
]

OPERATION_CHOICES = [
    "parse",
    "components",
    "query",
    "reconstruct",
]

# Populated by build_parser() so that other commands (namely `all`) can pull
# a subcommand's *real* defaults instead of hand-duplicating them, which
# silently drifts out of sync whenever a flag is added, renamed, or
# redefaulted.
SUBPARSERS: dict[str, argparse.ArgumentParser] = {}


# ============================================================================
# list-parsers
# ============================================================================

def run_list_parsers(args: argparse.Namespace) -> int:
    for adapter in get_adapters():
        print(f"  {adapter.name:<15} {adapter.available} {adapter.description}")



    return 0


# ============================================================================
# benchmark
# ============================================================================

def add_benchmark_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--parser",
        nargs="+",
        default=["urllib3", "urlps"],
        help="Parsers to benchmark",
    )

    parser.add_argument("--repeats", type=int, default=5, help="Timing repetitions per benchmark")
    parser.add_argument("--warmups", type=int, default=1, help="Warmup repetitions")

    parser.add_argument(
        "--repeated-parse",
        type=int,
        default=3,
        help="Number of parses per URL for the repeated-parse benchmark",
    )

    parser.add_argument("--simple", type=int, default=1000, help="Number of simple URLs")
    parser.add_argument("--complex", type=int, default=1000, dest="complex_", help="Number of complex URLs")
    parser.add_argument("--edge", type=int, default=1000, help="Number of generated edge-case URLs")
    parser.add_argument("--mixed", type=int, default=5000, help="Number of mixed URLs")

    parser.add_argument(
        "--pathological",
        action="store_true",
        help="Run only the hand-written pathological corpus",
    )

    parser.add_argument(
        "--operations",
        nargs="+",
        choices=OPERATION_CHOICES,
        default=list(OPERATION_CHOICES),
        help="Operations to benchmark",
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_RESULTS_JSON),
        help="JSON output file",
    )


def run_benchmark(args: argparse.Namespace) -> int:
    try:
        adapters = get_adapters(args.parser)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    datasets = build_datasets(
        simple=args.simple,
        complex_=args.complex_,
        edge=args.edge,
        mixed=args.mixed,
    )

    if args.pathological:
        datasets = [dataset for dataset in datasets if dataset.name == "pathological"]

    print()
    print("=" * 80)
    print("URL PARSER PERFORMANCE SUITE")
    print("=" * 80)

    print("\nParsers:")
    for adapter in adapters:
        print(f"  - {adapter.name}")

    print("\nDatasets:")
    for dataset in datasets:
        print(f"  - {dataset.name:<18} {dataset.size:,} URLs")

    print("\nOperations:")
    for operation in args.operations:
        print(f"  - {operation}")

    print()

    results = run_suite(
        adapters,
        datasets,
        operations=args.operations,
        repeats=max(1, args.repeats),
        warmups=max(0, args.warmups),
        repeated_parse=max(1, args.repeated_parse),
    )

    print_summary(results)

    save_results(results, args.output)

    print(f"\n[OK] Results written to:\n     {Path(args.output).resolve()}")

    return 0


# ============================================================================
# profile
# ============================================================================

def add_profile_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--parser", default="urlps", help="Parser to profile")
    parser.add_argument("--dataset", default="mixed", choices=DATASET_CHOICES)
    parser.add_argument("--operation", default="parse", choices=OPERATION_CHOICES)
    parser.add_argument("--repeats", type=int, default=25)
    parser.add_argument("--profile", default=str(DEFAULT_PROFILE_PROF), help="cProfile .prof output path")
    parser.add_argument("--text", default=str(DEFAULT_PROFILE_TXT), help="Human-readable profile output path")


def run_profile(args: argparse.Namespace) -> int:
    try:
        adapter = get_adapter(args.parser)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    datasets = build_datasets()
    dataset = next((d for d in datasets if d.name == args.dataset), None)

    if dataset is None:
        print(f"ERROR: Dataset not found: {args.dataset}", file=sys.stderr)
        return 2

    profile_parser(
        adapter,
        dataset,
        operation=args.operation,
        repeats=max(1, args.repeats),
        profile_path=args.profile,
        text_path=args.text,
    )

    return 0


# ============================================================================
# report
# ============================================================================

def add_report_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", default=str(DEFAULT_RESULTS_JSON), help="Benchmark results JSON")
    parser.add_argument("--output", default=str(DEFAULT_REPORT_HTML), help="HTML report output path")


def run_report(args: argparse.Namespace) -> int:
    input_path = Path(args.input)

    if not input_path.exists():
        print(
            f"ERROR: {input_path} does not exist.\n"
            "Run `python -m performance benchmark` first.",
            file=sys.stderr,
        )
        return 2

    results = load_results(input_path)

    try:
        report = generate_html(results)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    output_path = Path(args.output)
    output_path.write_text(report, encoding="utf-8")

    print(f"[OK] Generated:\n     {output_path.resolve()}")

    return 0


# ============================================================================
# concurrency
# ============================================================================

def add_concurrency_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--parser", nargs="+", default=["urlps"], help="Parsers to benchmark")
    parser.add_argument("--dataset", default="mixed", choices=DATASET_CHOICES)
    parser.add_argument("--operation", default="parse", choices=OPERATION_CHOICES)

    parser.add_argument(
        "--workers",
        nargs="+",
        type=int,
        default=[1, 2, 4, 8],
        help="Thread counts to measure throughput at",
    )

    parser.add_argument("--repeats", type=int, default=3, help="Timing repetitions per worker count")

    parser.add_argument(
        "--output",
        default=str(DEFAULT_CONCURRENCY_JSON),
        help="JSON output file",
    )


def run_concurrency(args: argparse.Namespace) -> int:
    try:
        adapters = get_adapters(args.parser)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    datasets = build_datasets()
    dataset = next((d for d in datasets if d.name == args.dataset), None)

    if dataset is None:
        print(f"ERROR: Dataset not found: {args.dataset}", file=sys.stderr)
        return 2

    print()
    print("=" * 80)
    print("CONCURRENCY BENCHMARK")
    print("=" * 80)
    print(
        "\nNote: CPython's GIL means pure-Python parsing work will not scale\n"
        "linearly with threads the way I/O-bound work would. This measures\n"
        "whether shared state (lru_cache locks, etc.) becomes a contention\n"
        "bottleneck under concurrent load -- not a parallel-speedup claim.\n"
    )

    results = [
        benchmark_concurrency(
            adapter,
            dataset,
            args.operation,
            worker_counts=tuple(args.workers),
            repeats=max(1, args.repeats),
        )
        for adapter in adapters
    ]

    print_concurrency_summary(results)

    save_concurrency_results(results, args.output)

    print(f"\n[OK] Results written to:\n     {Path(args.output).resolve()}")

    return 0


# ============================================================================
# compare
# ============================================================================

def add_compare_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("baseline", help="Baseline benchmark_results.json (the 'before')")
    parser.add_argument("candidate", help="Candidate benchmark_results.json (the 'after')")

    parser.add_argument(
        "--metric",
        default="microseconds_per_url",
        choices=["microseconds_per_url", "elapsed_seconds", "parses_per_second"],
        help="Metric to compare",
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=5.0,
        help="Percent change beyond which a row counts as a regression/improvement",
    )

    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit with status 1 if any row regressed past --threshold",
    )


def _load_rows(path: str) -> dict[tuple[str, str, str], dict]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))

    rows = {}

    for result in payload.get("results", []):
        key = (result["parser"], result["dataset"], result["operation"])
        rows[key] = result

    return rows


def run_compare(args: argparse.Namespace) -> int:
    try:
        baseline = _load_rows(args.baseline)
        candidate = _load_rows(args.candidate)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    higher_is_worse = args.metric != "parses_per_second"

    common_keys = sorted(set(baseline) & set(candidate))
    only_baseline = sorted(set(baseline) - set(candidate))
    only_candidate = sorted(set(candidate) - set(baseline))

    deltas = []

    for key in common_keys:
        before = baseline[key][args.metric]
        after = candidate[key][args.metric]

        if before == 0:
            continue

        pct = (after - before) / before * 100.0
        deltas.append((pct, key, before, after))

    # Worst regressions first.
    deltas.sort(key=lambda row: row[0] if higher_is_worse else -row[0], reverse=True)

    print()
    print("=" * 100)
    print(f"BENCHMARK COMPARISON  ({args.metric})")
    print("=" * 100)

    header = f"{'Parser':<10}{'Dataset':<16}{'Operation':<20}{'Baseline':>14}{'Candidate':>14}{'Change':>12}"
    print(header)
    print("-" * 100)

    regressions = 0
    improvements = 0

    for pct, (parser, dataset, operation), before, after in deltas:
        is_regression = (pct >= args.threshold) if higher_is_worse else (pct <= -args.threshold)
        is_improvement = (pct <= -args.threshold) if higher_is_worse else (pct >= args.threshold)

        if is_regression:
            regressions += 1
            marker = "!!"
        elif is_improvement:
            improvements += 1
            marker = "++"
        else:
            marker = "  "

        print(
            f"{parser:<10}{dataset:<16}{operation:<20}"
            f"{before:>14.4f}{after:>14.4f}{pct:>+11.2f}% {marker}"
        )

    print("-" * 100)
    print(f"Regressions (>= {args.threshold:g}% worse): {regressions}")
    print(f"Improvements (>= {args.threshold:g}% better): {improvements}")

    if only_baseline:
        print(f"\nOnly in baseline ({len(only_baseline)}):")
        for key in only_baseline:
            print(f"  - {' / '.join(key)}")

    if only_candidate:
        print(f"\nOnly in candidate ({len(only_candidate)}):")
        for key in only_candidate:
            print(f"  - {' / '.join(key)}")

    if args.fail_on_regression and regressions:
        return 1

    return 0


# ============================================================================
# all
# ============================================================================

def add_all_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--parser",
        nargs="+",
        default=None,
        help="Parsers to benchmark/profile (defaults to the benchmark command's default)",
    )

    parser.add_argument(
        "--skip-profile",
        action="store_true",
        help="Skip the cProfile step",
    )


def run_all(args: argparse.Namespace) -> int:
    # Pull each subcommand's *actual* defaults rather than re-declaring them
    # here, so `all` can never silently drift from `benchmark`/`profile`/`report`.
    benchmark_args = SUBPARSERS["benchmark"].parse_args([])
    report_args = SUBPARSERS["report"].parse_args([])
    profile_args = SUBPARSERS["profile"].parse_args([])

    if args.parser is not None:
        benchmark_args.parser = args.parser
        profile_args.parser = args.parser[0]

    code = run_benchmark(benchmark_args)
    if code != 0:
        return code

    code = run_report(report_args)
    if code != 0:
        return code

    if not args.skip_profile:
        code = run_profile(profile_args)
        if code != 0:
            return code

    print()
    print("=" * 80)
    print("COMPLETE")
    print("=" * 80)

    generated = [Path(benchmark_args.output), Path(report_args.output)]

    if not args.skip_profile:
        generated += [Path(profile_args.profile), Path(profile_args.text)]

    print("\nGenerated:")
    for path in generated:
        print(f"  {path}")

    return 0


# ============================================================================
# Entry point
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m performance",
        description="URL parser performance and compatibility test suite",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"urlps {urlps.__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    commands = [
        ("benchmark", "Run the benchmark suite and write a JSON results file", add_benchmark_arguments, run_benchmark),
        ("profile", "cProfile a single parser/dataset/operation combination", add_profile_arguments, run_profile),
        ("report", "Generate an HTML dashboard from a benchmark results JSON file", add_report_arguments, run_report),
        ("concurrency", "Measure throughput at increasing thread counts", add_concurrency_arguments, run_concurrency),
        ("compare", "Diff two benchmark JSON files and flag regressions", add_compare_arguments, run_compare),
        ("list-parsers", "List available parser adapters", None, run_list_parsers),
        ("all", "Run benchmark, then report, then profile, using default settings", add_all_arguments, run_all),
    ]

    for name, help_text, add_arguments, func in commands:
        subparser = subparsers.add_parser(name, help=help_text)

        if add_arguments is not None:
            add_arguments(subparser)

        subparser.set_defaults(func=func)
        SUBPARSERS[name] = subparser

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
