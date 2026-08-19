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

This module owns argument parsing and wiring only -- all console output goes
through performance.output, and all benchmarking logic lives in
performance.benchmark_suite.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import urlps

from .adapters import available_categories, get_adapter, get_adapters, get_adapters_by_tags
from .adapters._models import ParserAdapter
from .benchmark_suite import (
    benchmark_concurrency,
    build_tunable_datasets,
    count_planned_steps,
    profile_parser,
    run_suite,
)
from .output import (
    CompareRow,
    LiveProgress,
    error,
    named_list,
    print_categories,
    print_compare_exclusive,
    print_compare_footer,
    print_compare_header,
    print_compare_table,
    print_complete,
    print_concurrency_header,
    print_concurrency_summary,
    print_dataset_list,
    print_parser_availability,
    print_profile_complete,
    print_profile_start,
    print_report_generated,
    print_results_written,
    print_suite_header,
    print_summary,
    save_concurrency_results,
    save_results,
)
from .performance_report import generate_html, load_results
from .tuner import TunableDataset
from .url_cases import (
    MALICIOUS_EXPECTATIONS,
    MALICIOUS_URLS,
    MODIFY_OPERATIONS,
    PATHOLOGICAL_EXPECTATIONS,
    PATHOLOGICAL_URLS,
    URLDataset,
    build_datasets,
)

PERFORMANCE_DIR = Path(__file__).resolve().parent
DATA_DIR = PERFORMANCE_DIR / "data"

DEFAULT_RESULTS_JSON = DATA_DIR / "benchmark_results.json"
DEFAULT_REPORT_HTML = DATA_DIR / "performance_report.html"
DEFAULT_PROFILE_PROF = DATA_DIR / "profile_results.prof"
DEFAULT_PROFILE_TXT = DATA_DIR / "profile_results.txt"
DEFAULT_CONCURRENCY_JSON = DATA_DIR / "concurrency_results.json"

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
    "modify_path",
    "modify_query",
    "modify_host",
    "modify_fragment",
    "validate",
    "normalize",
]

# Populated by build_parser() so that other commands (namely `all`) can pull
# a subcommand's *real* defaults instead of hand-duplicating them, which
# silently drifts out of sync whenever a flag is added, renamed, or
# redefaulted.
SUBPARSERS: dict[str, argparse.ArgumentParser] = {}

DEFAULT_PARSER_NAMES = ["urllib3", "urlps"]

#: Reserved --parser name meaning "every available adapter except the ones
#: tagged network" (see _resolve_parser_names) -- never a real adapter name.
ALL_PARSERS = "all"


def _add_parser_selection_arguments(parser: argparse.ArgumentParser, *, default_names: list[str] | None) -> None:
    """
    Shared --parser/--categories flags for any command that benchmarks a
    selectable set of adapters (`benchmark`, `concurrency`).
    """
    parser.add_argument(
        "--parser",
        nargs="+",
        default=None,
        help=(
            "Parsers to benchmark by name (see `list-parsers`), or "
            f"'{ALL_PARSERS}' for every available adapter except those "
            "tagged 'network' (they do real per-call I/O -- name them "
            "explicitly, e.g. `--parser all url-jail`, to include them "
            "anyway). "
            f"Default: {' '.join(default_names)}, or every adapter matching "
            "--categories if that's given instead."
        ),
    )

    parser.add_argument(
        "--categories",
        nargs="+",
        default=None,
        metavar="TAG",
        help=(
            "Only benchmark adapters tagged with any of these categories "
            "(see `list-categories`), e.g. --categories parser validation. "
            "Combined with --parser (if both given), narrows that named "
            "selection down further instead of replacing it."
        ),
    )


def _resolve_parser_names(names: list[str]) -> list[ParserAdapter]:
    """
    Resolve a --parser name list, expanding the `all` sentinel if present.

    `all` means every available adapter *except* network-tagged ones (they
    do real per-call DNS/HTTP I/O -- see _models.py's tag vocabulary -- so
    silently sweeping them into "all" would make a routine benchmark run
    both far slower and dependent on network access without the caller
    asking for that). Any other names given alongside `all` are still
    included explicitly -- `--parser all url-jail` is how you opt back in.
    """
    if ALL_PARSERS not in names:
        return get_adapters(names)

    explicit_names = [name for name in names if name != ALL_PARSERS]

    adapters = [adapter for adapter in get_adapters() if "network" not in adapter.tags]

    seen = {adapter.name for adapter in adapters}
    for adapter in get_adapters(explicit_names):
        if adapter.name not in seen:
            seen.add(adapter.name)
            adapters.append(adapter)

    return adapters


def _select_adapters(
    parser_names: list[str] | None,
    categories: list[str] | None,
    *,
    default_names: list[str],
) -> list[ParserAdapter]:
    """
    Resolve --parser/--categories into a concrete adapter list.

    - Neither given: the command's historical default (by name).
    - --parser only: exactly those adapters (`all` expands per
      _resolve_parser_names).
    - --categories only: every available adapter carrying any of those tags
      (e.g. --categories security pulls in every security-focused adapter
      without having to name each one).
    - Both: the (possibly `all`-expanded) named adapters, further filtered
      down to those also carrying at least one of the given tags.
    """
    if parser_names is not None:
        adapters = _resolve_parser_names(parser_names)

        if categories:
            wanted = set(categories)
            adapters = [adapter for adapter in adapters if adapter.tags & wanted]

        return adapters

    if categories:
        return get_adapters_by_tags(categories)

    return get_adapters(default_names)


# ============================================================================
# list-parsers
# ============================================================================

def add_list_parsers_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--categories",
        nargs="+",
        default=None,
        metavar="TAG",
        help="Only list adapters tagged with any of these categories (see `list-categories`)",
    )


def run_list_parsers(args: argparse.Namespace) -> int:
    # available_only=False: this command's job is to show *which* adapters
    # are unavailable (and why) alongside the available ones, so it must
    # not filter them out before they ever reach the display.
    if args.categories:
        adapters = get_adapters_by_tags(args.categories, available_only=False)
    else:
        adapters = get_adapters(available_only=False)

    print_parser_availability(adapters)
    return 0


# ============================================================================
# list-categories
# ============================================================================

def run_list_categories(args: argparse.Namespace) -> int:
    print_categories(available_categories(), get_adapters(available_only=False))
    return 0


# ============================================================================
# benchmark
# ============================================================================

def add_benchmark_arguments(parser: argparse.ArgumentParser) -> None:
    _add_parser_selection_arguments(parser, default_names=DEFAULT_PARSER_NAMES)

    parser.add_argument("--repeats", type=int, default=5, help="Timing repetitions per benchmark")
    parser.add_argument("--warmups", type=int, default=1, help="Warmup repetitions")

    parser.add_argument(
        "--repeated-parse",
        type=int,
        default=3,
        help="Number of parses per URL for the repeated-parse benchmark",
    )

    parser.add_argument("--simple", type=int, default=None, help="Number of simple URLs (default: auto-tuned)")
    parser.add_argument("--complex", type=int, default=None, dest="complex_", help="Number of complex URLs (default: auto-tuned)")
    parser.add_argument("--edge", type=int, default=None, help="Number of generated edge-case URLs (default: auto-tuned)")
    parser.add_argument("--mixed", type=int, default=None, help="Number of mixed URLs (default: auto-tuned)")
    parser.add_argument("--rand", type=int, default=None, help="Number of random string (default: auto-tuned)")

    parser.add_argument(
        "--tune",
        dest="tune",
        action="store_true",
        default=True,
        help="Auto-tune dataset sizes on the fly so each parser/operation/dataset run takes ~50-500ms (default: on)",
    )
    parser.add_argument(
        "--no-tune",
        dest="tune",
        action="store_false",
        help="Disable auto-tuning; unset sizes fall back to fixed defaults (1000 URLs)",
    )

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


FALLBACK_DATASET_SIZES = {
    "simple": 1000,
    "complex_": 1000,
    "edge": 1000,
    "mixed": 1000,
    "rand": 1000,
}

# Which tunable-dataset names share each coarse CLI knob's starting size.
_KNOB_TO_TUNABLE_NAMES = {
    "simple": ["simple"],
    "complex_": ["complex"],
    "edge": ["ipv6", "invalid-port", "long-query", "encoded", "relative"],
    "mixed": ["mixed"],
    "rand": ["random-strings"],
}


def _build_benchmark_datasets(args: argparse.Namespace) -> list[URLDataset | TunableDataset]:
    """
    Build the dataset list for `benchmark`: `pathological`/`malicious` are
    always fixed, hand-written corpora; the rest either self-tune on the fly
    (--tune, the default) or use fixed sizes (--no-tune).
    """
    static_datasets = [
        URLDataset(
            "pathological",
            list(PATHOLOGICAL_URLS),
            skip_repeated_parse=True,
            per_url_expectations=PATHOLOGICAL_EXPECTATIONS,
        ),
        URLDataset(
            "malicious",
            list(MALICIOUS_URLS),
            excluded_operations=frozenset(MODIFY_OPERATIONS),
            skip_repeated_parse=True,
            per_url_expectations=MALICIOUS_EXPECTATIONS,
        ),
    ]

    if args.tune:
        starting_sizes: dict[str, int] = {}

        for knob, names in _KNOB_TO_TUNABLE_NAMES.items():
            value = getattr(args, knob)
            if value is not None:
                for name in names:
                    starting_sizes[name] = value

        return [*static_datasets, *build_tunable_datasets(starting_sizes=starting_sizes)]

    sizes = dict(FALLBACK_DATASET_SIZES)
    for knob in ("simple", "complex_", "edge", "mixed", "rand"):
        value = getattr(args, knob)
        if value is not None:
            sizes[knob] = value

    tunable_off = build_datasets(
        simple=sizes["simple"],
        complex_=sizes["complex_"],
        edge=sizes["edge"],
        mixed=sizes["mixed"],
        rand=sizes["rand"],
    )

    # build_datasets() also produces its own pathological/malicious entries;
    # drop those in favor of the ones already built above so there's exactly
    # one of each regardless of --tune.
    return static_datasets + [d for d in tunable_off if d.name not in ("pathological", "malicious")]


def run_benchmark(args: argparse.Namespace) -> int:
    try:
        adapters = _select_adapters(args.parser, args.categories, default_names=DEFAULT_PARSER_NAMES)
    except ValueError as exc:
        error(str(exc))
        return 2

    if not adapters:
        error("No adapters matched --parser/--categories. See `list-parsers` / `list-categories`.")
        return 2

    datasets = _build_benchmark_datasets(args)

    if args.pathological:
        datasets = [dataset for dataset in datasets if dataset.name == "pathological"]

    print_suite_header()

    named_list("Parsers", [adapter.name for adapter in adapters])
    print_dataset_list(datasets)
    named_list("Operations", args.operations)

    repeated_parse = max(1, args.repeated_parse)

    progress = LiveProgress(
        total_parsers=len(adapters),
        total_steps=count_planned_steps(adapters, datasets, args.operations, repeated_parse=repeated_parse),
    )
    progress.print_header()

    results = run_suite(
        adapters,
        datasets,
        operations=args.operations,
        repeats=max(1, args.repeats),
        warmups=max(0, args.warmups),
        repeated_parse=repeated_parse,
        on_parser_start=lambda adapter: progress.parser_started(adapter.name),
        on_dataset_start=lambda dataset: progress.dataset_started(
            dataset.name,
            dataset.size,
            tunable=isinstance(dataset, TunableDataset),
        ),
        on_operation_start=progress.operation_started,
        on_result=progress.result,
    )

    print_summary(results)

    output_path = save_results(results, args.output)
    print_results_written(output_path)

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
        error(str(exc))
        return 2

    datasets = build_datasets()
    dataset = next((d for d in datasets if d.name == args.dataset), None)

    if dataset is None:
        error(f"Dataset not found: {args.dataset}")
        return 2

    print_profile_start(adapter.name, dataset.name, args.operation)

    profile_path, text_path = profile_parser(
        adapter,
        dataset,
        operation=args.operation,
        repeats=max(1, args.repeats),
        profile_path=args.profile,
        text_path=args.text,
    )

    print_profile_complete(profile_path, text_path)

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
        error(f"{input_path} does not exist.\nRun `python -m performance benchmark` first.")
        return 2

    results = load_results(input_path)

    try:
        report = generate_html(results)
    except ValueError as exc:
        error(str(exc))
        return 2

    output_path = Path(args.output)
    output_path.write_text(report, encoding="utf-8")
    print_report_generated(output_path)

    return 0


# ============================================================================
# concurrency
# ============================================================================

def add_concurrency_arguments(parser: argparse.ArgumentParser) -> None:
    _add_parser_selection_arguments(parser, default_names=["urlps"])
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
        adapters = _select_adapters(args.parser, args.categories, default_names=["urlps"])
    except ValueError as exc:
        error(str(exc))
        return 2

    if not adapters:
        error("No adapters matched --parser/--categories. See `list-parsers` / `list-categories`.")
        return 2

    datasets = build_datasets()
    dataset = next((d for d in datasets if d.name == args.dataset), None)

    if dataset is None:
        error(f"Dataset not found: {args.dataset}")
        return 2

    print_concurrency_header()

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

    output_path = save_concurrency_results(results, args.output)
    print_results_written(output_path)

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
        error(str(exc))
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

    print_compare_header(args.metric)

    regressions = 0
    improvements = 0
    compare_rows = []

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

        compare_rows.append(CompareRow(parser, dataset, operation, before, after, pct, marker))

    print_compare_table(compare_rows)
    print_compare_footer(regressions, improvements, args.threshold)
    print_compare_exclusive("baseline", only_baseline)
    print_compare_exclusive("candidate", only_candidate)

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

    generated = [Path(benchmark_args.output), Path(report_args.output)]

    if not args.skip_profile:
        generated += [Path(profile_args.profile), Path(profile_args.text)]

    print_complete(generated)

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
        ("list-parsers", "List available parser adapters", add_list_parsers_arguments, run_list_parsers),
        ("list-categories", "List adapter category tags and which adapters carry each", None, run_list_categories),
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
