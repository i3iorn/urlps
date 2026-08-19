# Performance Suite

Benchmark, profile, and compare URL parsers, validators, normalizers, and
URL-security scanners (`urlps` vs. 16 other libraries) against a range of
generated and hand-written URL corpora.

Not every adapter is a full parser -- `validators`/`urlpolice` only judge a
URL valid/invalid, `url-normalize` only canonicalizes a string, and neither
has "components" to extract or a `with_host()` to exercise. Each adapter is
tagged with **categories** (`parser`, `validation`, `normalization`,
`security`, `http-client`, `rfc3986`, `whatwg`, `stdlib`, `network`) and only
benchmarked on the operations it actually supports -- see [Categories](#categories)
below.

| Adapter | Categories | Notes |
|---|---|---|
| `urlps` | parser, rfc3986, validation, security | this project |
| `urllib` | parser, rfc3986, stdlib | |
| `urllib3` | parser, rfc3986 | |
| `rfc3986` | parser, rfc3986, validation | |
| `rfc3987` | parser, rfc3986, validation | URI **and** IRI |
| `uritools` | parser, rfc3986 | |
| `furl` | parser, rfc3986 | |
| `yarl` | parser, rfc3986 | |
| `hyperlink` | parser | immutable, `.replace()` |
| `pywhatwgurl` | parser, whatwg | browser-spec parsing |
| `httpx` | parser, http-client | `httpx.URL` |
| `requests` | http-client | parse/reconstruct only -- no component model |
| `pydantic` | parser, validation | `AnyUrl`/`HttpUrl` |
| `validators` | validation | boolean-ish, no parsed object |
| `url-normalize` | normalization | string in, canonical string out |
| `urlpolice` | validation, security | SSRF/XSS-focused; see caveat below |
| `url-jail` | security, network | **does live DNS lookups per call** -- see caveat below |

Two adapters carry a caveat worth knowing about before benchmarking them:

- **`url-jail`** performs real DNS resolution (and potentially live HTTP
  requests) on every `validate` call -- confirmed empirically at ~30ms/call
  vs. microseconds for every other adapter. Its timings aren't comparable to
  the rest of the suite, results depend on network access, and a full-corpus
  run against it will take drastically longer. It's tagged `network` and
  never pulled in by a default `--parser`/`--categories` selection -- only
  when named explicitly.
- **`urlpolice`** (0.1.2) has two real bugs surfaced by benchmarking it
  against the pathological/malicious corpora: it doesn't guard against
  `urllib.parse`'s lazy `.port` raising `ValueError` on a malformed port,
  and several adversarial inputs (`"http://_"`, decimal/hex-encoded-IP SSRF
  attempts, `*.local` hosts) trigger catastrophic-backtracking-shaped
  slowdowns of **~2.7 seconds per call**. Both are caught and recorded as
  ordinary benchmark failures rather than crashing the suite, but a
  `urlpolice` run against those datasets will be dramatically slower than
  every other adapter -- that's the library, not this benchmark.

All commands are run through a single entry point:

```bash
python -m performance <command> [options]
```

Run `python -m performance --help` or `python -m performance <command> --help`
for the full flag list at any time.

## Commands

### `list-parsers`

List the registered parser adapters -- name, availability (and why, if an
optional dependency isn't installed), description, and category tags.

```bash
python -m performance list-parsers

# Only adapters tagged "security" or "validation"
python -m performance list-parsers --categories security validation
```

### `list-categories`

List every category tag in use and which (available) adapters carry it --
useful for discovering what `--categories` accepts.

```bash
python -m performance list-categories
```

### `benchmark`

Run the timing + compatibility suite and write a JSON results file.

```bash
# Default: urllib3 vs. urlps, all datasets, all operations
python -m performance benchmark

# Specific parsers, by name
python -m performance benchmark --parser urlps rfc3986

# Every adapter in a category, without naming each one
python -m performance benchmark --categories validation

# Named parsers, further narrowed to ones that are also in a category
python -m performance benchmark --parser urlps rfc3986 validators --categories validation

# Every adapter except the ones that do real network I/O (url-jail)
python -m performance benchmark --parser all

# ...plus that one anyway, named explicitly
python -m performance benchmark --parser all url-jail

# Only the hand-written pathological corpus (fast sanity pass)
python -m performance benchmark --pathological

# Only certain operations, with more repeats for stabler timings
python -m performance benchmark --operations parse components --repeats 10 --warmups 2

# Custom output location
python -m performance benchmark --output /tmp/results.json
```

Key flags: `--parser`, `--categories` (see [Categories](#categories)),
`--operations {parse,components,query,reconstruct,modify_path,modify_query,
modify_host,modify_fragment,validate,normalize}`, `--repeats`, `--warmups`,
`--repeated-parse`, `--simple/--complex/--edge/--mixed` (corpus sizes),
`--tune/--no-tune`, `--pathological`, `--output`.

#### Categories

`--parser`/`--categories` on `benchmark` and `concurrency` compose:

- Neither given: the command's historical default (`urllib3 urlps` for
  `benchmark`; `urlps` for `concurrency`).
- `--parser` only: exactly those adapters, by name -- or `--parser all` for
  every available adapter *except* ones tagged `network` (they do real
  per-call DNS/HTTP I/O -- see the `url-jail` caveat above -- so `all`
  deliberately doesn't sweep them in). Name one alongside `all` to include
  it anyway: `--parser all url-jail`.
- `--categories` only: every available adapter carrying *any* of the given
  tags (union, not intersection) -- e.g. `--categories security` pulls in
  every security-focused adapter without listing each one, and stays
  correct as more get added.
- Both: the named adapters, further filtered down to the ones that also
  carry at least one of the given tags.

Whichever adapters end up selected, each only runs the operations it
actually supports (see the adapter table above) -- `--operations` is a
ceiling, not a guarantee every adapter attempts every one of them. A pure
validator asked to run `parse`/`components`/`reconstruct` simply skips
those rather than recording a wall of "not supported" failures for
operations that were never applicable. Run `list-categories` to see what
tags exist and which adapters carry each.

**Auto-tuned dataset sizes.** Any of `--simple`/`--complex`/`--edge`/
`--mixed` left unset is auto-tuned (on by default) so each parser/operation/
dataset run keeps you waiting somewhere around 50-500ms -- with no separate
calibration pass. Each tunable dataset carries its own size and nudges it
after every real (parser, operation) run against it: too slow (>500ms)
shrinks it, too fast (<50ms) grows it, and the change is permanent -- it
carries into the next operation, and into the next parser's pass over the
same dataset, so sizes settle over the course of the run itself. The time
that decides this is the *wall-clock time you actually waited* for that
run -- warmups, every `--repeats` pass, the distribution pass, the memory
pass, all of it -- not the single headline `elapsed_seconds` batch number
that ends up in the results (which is only a fraction of that wait). (An
earlier version both ran a dedicated calibration pass upfront and tuned off
that headline number; besides being slow, timing small throwaway samples
was dominated by timer/GC noise and produced wildly inconsistent sizes run
to run, and tuning off `elapsed_seconds` didn't reflect how long the
developer was actually stuck waiting. Measuring the real, already-happening
runs' wall-clock time fixed both.) A size you pass explicitly sets that
dataset's *starting* size rather than disabling tuning for it. `edge`
seeds five independently-tunable datasets (`ipv6`/`invalid-port`/
`long-query`/`encoded`/`relative`); `pathological` and `malicious` are
fixed hand-written corpora and aren't tunable. Pass `--no-tune` for fully
fixed, reproducible sizes (useful for `compare` baselines).

The `modify_*` operations benchmark each parser's mutation API (`with_path`
/ `.set()` / `._replace()` / `copy_with()`, depending on the parser) by
replacing one component with a fixed value and timing the result -- this is
a different code path than `parse` + read, and exercises validation that
only runs on rebuild (e.g. urlps re-validating a URL after `with_host()`).
`modify_host` in particular differs by parser: some expose `host` directly
(urlps, yarl, urllib3), others require rebuilding an authority/netloc string
around it (urllib, rfc3986) while preserving existing userinfo/port.

Not every operation is informative on every dataset. `URLDataset` carries
two knobs the suite checks per (dataset, operation) before running anything:
`excluded_operations` (skip specific operations entirely for that dataset)
and `skip_repeated_parse` (skip the repeated-parse benchmark for it). The
`malicious` corpus sets both: `modify_*` on a URL from the adversarial
corpus tests nothing about *that* corpus's purpose (whether the original
URL gets flagged) — it's the same `modify()` codepath every other dataset
already covers — and repeated-parse exists to characterize realistic
repeated-fetch throughput, which a small hand-curated correctness corpus
doesn't need at 3x the cost. `pathological` sets `skip_repeated_parse` only
(its `modify_*` coverage of malformed components is exactly the point of
that corpus). `count_planned_steps()`/`run_suite()` both honor these, so
the live progress counter's total always matches what actually runs.

### Expected outcomes

Every URL in the suite can carry a *known expected outcome* -- not just
"did the parser accept or reject it," but "was that the right call." This
is what feeds the report's **Correctness** tab.

`URLDataset.expectation`/`.per_url_expectations` (a single value for the
whole dataset, or one per URL for heterogeneous hand-written corpora) hold
one of four values (see `EXPECTATION_*` in `url_cases/_models.py`):

- **`valid`** -- ordinary well-formed input; should be accepted.
- **`invalid`** -- malformed under any reasonable interpretation of the URI
  grammar (a raw control character, a non-digit port, a truncated IPv6
  literal, ...); a correct parser should reject it.
- **`unsafe`** -- syntactically valid, semantically dangerous (an SSRF
  target, credential smuggling, path traversal, a homograph domain, ...).
  Accepting it is *not* a parsing bug -- most of the `malicious` corpus is
  this, not `invalid`. Only adapters tagged `security` are scored against
  it; a plain RFC parser correctly accepting `http://169.254.169.254/` is
  not a mistake.
- **`ambiguous`** -- genuinely disputed among reasonable, spec-compliant
  parsers (WHATWG treats backslashes as slashes for special schemes, RFC
  3986 doesn't; numeric ports past 65535 are valid `*DIGIT` grammar but out
  of range; IPv6 zone-ID/IPvFuture support is optional; DNS-dependent SSRF
  can't be judged without a live lookup). Never scored either way.

Every generated dataset is internally homogeneous and gets a single
dataset-wide `expectation` (`simple`/`complex`/`ipv6`/`long-query`/
`encoded`/`relative` are `valid`, `invalid-port` is `invalid`); `mixed` and
`random-strings` are left unannotated (`unknown`) since they deliberately
blend outcomes or are outright random. `malicious` and `pathological` are
hand-annotated per-URL, section by section (see the docstrings at the top
of `url_cases/malicious.py`/`pathological.py`) -- best-effort
classifications, not a formal grammar checker's output.

`benchmark_operation()` scores this in a dedicated pass (like the latency
distribution/memory measurements), storing per-expectation-bucket
correct/incorrect counts on `BenchmarkResult.expectation_accuracy` without
touching the headline timing numbers.

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
- **`memory`** — `peak_bytes` (high-water mark of traced Python allocations
  during a single pass over the dataset), `bytes_per_url` (`peak_bytes /
  urls`), and `object_count` (distinct allocations still live at the end of
  the pass, i.e. what's actually retained rather than every temporary
  created along the way). Measured via `tracemalloc` in its own dedicated
  pass, same rationale as `distribution` -- so its bookkeeping overhead
  never pollutes `elapsed_seconds`/`microseconds_per_url`. Only reflects
  Python-level allocations; a parser doing real work in a C extension won't
  show it here. Printed as part of `benchmark`'s console summary (worst-case
  peak / average bytes-per-URL / average object count per parser+operation)
  and as its own table + per-row columns in `report`'s HTML output.

### `report`

Turn a `benchmark` JSON file into an interactive HTML dashboard.

```bash
python -m performance report
python -m performance report --input results.json --output report.html
```

The dashboard is tabbed rather than one long page, so each tab stays
focused on one question instead of every table/chart competing for
attention at once:

- **Overview** — headline cards (parsers, URLs, failure rate, peak
  throughput, median P95, peak memory) + per-parser totals.
- **Timing** — grouped bar charts per operation (µs/URL and, in a second
  section, parses/sec), every dataset on one shared axis with quick-jump
  pills; toggle a parser off via the chart legend to compare the rest.
  Also a relative-speed table (fastest parser per operation vs. the rest)
  and a searchable detail table with min/max/jitter spread across repeats
  (how noisy the measurement was, not just its median).
- **Distribution** — p50/p95/p99/max latency, accepted-vs-rejected mean,
  and µs/byte, per parser/dataset/operation. Not shown anywhere before.
- **Errors** — a top-error-types chart plus the full parser/operation/
  error-type/count breakdown (previously only visible as an inline text
  blob per row).
- **Memory** / **Cache** — shown only when the run has that data.
- **Security** — how each parser handles the hand-written malicious/
  adversarial URL corpus (SSRF, path traversal, homograph spoofing, etc.);
  rejecting a URL is the good outcome here, the inverse of every other
  tab's success/failure framing. Shown only when that dataset is present.
- **Correctness** — whether each parser's accept/reject verdict matches
  each URL's *known* expected outcome (see "Expected outcomes" below),
  across every dataset that carries that data, not just the malicious
  corpus. This is the only tab that checks a parser's behavior against a
  real right answer instead of just reporting what happened.
- **Raw Data** — the full unaggregated result set, searchable, for anyone
  who wants the same numbers the other tabs already reshaped.

Charts render lazily (only once their tab is first opened) so Chart.js
never has to size a canvas inside a hidden panel.

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
| `adapters/` | `ParserAdapter` wrappers around each URL parser/validator/normalizer under test, each tagged with categories (`_models.py`) |
| `url_cases/` | Corpus generators (`generators.py`) + the hand-written pathological/malicious corpora (`pathological.py`/`malicious.py`), assembled by `build_datasets()` in `datasets.py`. Everything re-exported from the package root, same as before it was a single module. |
| `benchmark_suite.py` | Timing/behavior engine used by `benchmark` and `profile` |
| `tuner.py` | Self-adjusting dataset sizing used by `--tune` (on by default) |
| `output/` | Terminal styling (`theme.py`), layout primitives (`layout.py`), the live `benchmark` console stream (`progress.py`), listings/persistence/summary/compare/concurrency/command output. Everything re-exported from the package root, same as before it was a single module. |
| `performance_report/` | HTML dashboard generator used by `report`: result loading (`_io.py`), aggregation (`aggregate.py`), reusable HTML snippets (`components.py`), per-tab builders (`tabs.py`), stylesheet/script (`css.py`/`js.py`), and the top-level `generate_html()` orchestrator (`page.py`). Everything re-exported from the package root, same as before it was a single module. |
| `test_benchmarks.py` | `pytest-benchmark` integration |

Generated artifacts (`benchmark_results.json`, `performance_report.html`,
`profile_results.*`) are gitignored — they're outputs, not source.
