# Performance Suite

Benchmark, profile, and compare URL parsers (`urlps` vs. `urllib`, `rfc3986`,
`urllib3`, `furl`, `yarl`) against a range of generated and hand-written URL
corpora.

All commands are run through a single entry point:

```bash
python -m performance <command> [options]
```

Run `python -m performance --help` or `python -m performance <command> --help`
for the full flag list at any time.

## Commands

### `list-parsers`

List the registered parser adapters.

```bash
python -m performance list-parsers
```

### `benchmark`

Run the timing + compatibility suite and write a JSON results file.

```bash
# Default: urllib vs. urlps, all datasets, all operations
python -m performance benchmark

# Specific parsers
python -m performance benchmark --parser urlps rfc3986

# Only the hand-written pathological corpus (fast sanity pass)
python -m performance benchmark --pathological

# Only certain operations, with more repeats for stabler timings
python -m performance benchmark --operations parse components --repeats 10 --warmups 2

# Custom output location
python -m performance benchmark --output /tmp/results.json
```

Key flags: `--parser`, `--operations {parse,components,query,reconstruct}`,
`--repeats`, `--warmups`, `--repeated-parse`, `--simple/--complex/--edge/--mixed`
(corpus sizes), `--pathological`, `--output`.

Each result now carries more than a headline μs/URL number:

- **`distribution`** — per-URL latency percentiles (p50/p95/p99/max),
  measured in a dedicated single pass over every URL individually (not
  averaged across the `--repeats` batches used for `elapsed_seconds`, so
  per-call timer overhead never pollutes the headline throughput number).
  Split into `overall`, `accepted` (URLs that passed) and `rejected` (URLs
  the parser refused) — comparing `accepted.mean_us` vs. `rejected.mean_us`
  tells you whether rejection is cheap or is accidentally the *slow* path,
  which matters for a security-focused parser handling adversarial input.
  Also includes `microseconds_per_byte`, which separates fixed per-call
  overhead from O(n) scanning cost — useful when a dataset's slowness could
  be either.
- **`cache_delta`** — hit/miss counts for every internal cache, for parsers
  whose adapter exposes a `cache_info()` hook (currently just `urlps`, via
  `urlps.get_cache_info()`). `None` for parsers with no such introspection.
  Printed as part of `benchmark`'s console summary and as its own table in
  `report`'s HTML output.

### `report`

Turn a `benchmark` JSON file into an interactive HTML dashboard.

```bash
python -m performance report
python -m performance report --input results.json --output report.html
```

### `profile`

cProfile a single parser/dataset/operation combination — use this to dig into
*why* something is slow after `benchmark` tells you *that* it's slow.

```bash
python -m performance profile --parser urlps --dataset mixed --operation parse
```

Writes a raw `.prof` file (open with `snakeviz` or `pstats`) and a
human-readable `.txt` summary.

### `concurrency`

Measure throughput at increasing thread counts.

```bash
python -m performance concurrency --parser urlps --workers 1 2 4 8
```

CPython's GIL means pure-Python parsing work will not scale linearly with
threads the way I/O-bound work would — this isn't measuring parallel
speedup. It's here to surface whether *shared state* (an `lru_cache`'s
internal lock, or the audit manager before a recent fix removed its
per-parse `Lock()` allocation) becomes a contention bottleneck under
concurrent load, which a single-threaded benchmark can never show. Writes
`concurrency_results.json` by default; not currently wired into `report`'s
HTML dashboard.

### `compare`

Diff two `benchmark` JSON files and flag regressions/improvements. Useful in
CI to catch a PR that quietly makes urlps slower.

```bash
python -m performance compare baseline.json benchmark_results.json

# Fail the command (exit 1) if anything regressed by 10%+
python -m performance compare baseline.json benchmark_results.json \
    --threshold 10 --fail-on-regression

# Compare a different metric
python -m performance compare baseline.json benchmark_results.json \
    --metric parses_per_second
```

Rows are sorted worst-regression-first and marked `!!` (regression) or `++`
(improvement) once past `--threshold` percent change. Benchmarks present in
only one of the two files are listed separately rather than silently dropped.

### `all`

Run `benchmark` → `report` → `profile` back to back with sane defaults.

```bash
python -m performance all

# Skip the (slower) profiling step
python -m performance all --skip-profile

# Override which parser(s) get benchmarked/profiled
python -m performance all --parser urlps
```

## Typical workflow

```bash
# 1. Establish a baseline before making changes
python -m performance benchmark --output performance/baseline.json

# 2. Make your changes to src/urlps ...

# 3. Re-run and compare
python -m performance benchmark
python -m performance compare performance/baseline.json performance/benchmark_results.json --fail-on-regression

# 4. Look at the dashboard / profile if something regressed
python -m performance report
python -m performance profile --parser urlps --dataset mixed
```

## pytest-benchmark integration

Separate from the manual suite above, `test_benchmarks.py` wires the same
adapters into `pytest-benchmark` for micro-benchmarking individual
operations:

```bash
pytest performance/test_benchmarks.py -v --benchmark-only
```

## Layout

| Path | Purpose |
|---|---|
| `cli.py` | Single CLI entry point (`python -m performance`) |
| `adapters/` | `ParserAdapter` wrappers around each URL parser under test |
| `url_cases.py` | Corpus generators + the hand-written pathological corpus |
| `benchmark_suite.py` | Timing/behavior engine used by `benchmark` and `profile` |
| `performance_report.py` | HTML dashboard generator used by `report` |
| `test_benchmarks.py` | `pytest-benchmark` integration |

Generated artifacts (`benchmark_results.json`, `performance_report.html`,
`profile_results.*`) are gitignored — they're outputs, not source.
