"""
Generate an interactive HTML dashboard from benchmark_results.json.
"""

from __future__ import annotations

import html
import json
import time
from collections import defaultdict
from pathlib import Path


PERFORMANCE_DIR = Path(__file__).resolve().parent

INPUT_FILE = PERFORMANCE_DIR / "benchmark_results.json"
OUTPUT_FILE = PERFORMANCE_DIR / "performance_report.html"


def load_results(path: str | Path = INPUT_FILE) -> list[dict]:
    with Path(path).open("r", encoding="utf-8") as fh:
        payload = json.load(fh)

    return payload.get("results", [])


def esc(value: object) -> str:
    return html.escape(str(value))


# ============================================================================
# Aggregation
#
# Everything below only reshapes/sums the numbers that are already in each
# result row. Nothing here computes a ratio, percent difference, or "winner"
# between parsers -- when multiple parsers are present, the report puts their
# raw numbers side by side (same chart, same table) and leaves the reading of
# them to the viewer.
# ============================================================================

def _per_parser_summary(results: list[dict]) -> list[dict]:
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
        summary.append(
            {
                "parser": bucket["parser"],
                "urls": urls,
                "successful": bucket["successful"],
                "failed": bucket["failed"],
                "success_rate": (bucket["successful"] / urls * 100.0) if urls else 0.0,
                "microseconds_per_url": (bucket["elapsed_seconds"] / urls * 1_000_000.0) if urls else 0.0,
            }
        )

    return sorted(summary, key=lambda row: row["parser"])


def _grouped_by_operation(results: list[dict], metric: str) -> dict[str, dict]:
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


def _split_by_scale(shaped_by_operation: dict[str, dict]) -> dict[str, list[dict]]:
    """
    Split each operation's datasets into two scale-homogeneous groups so a
    chart mixing microsecond-scale and hundred-microsecond-scale datasets on
    one shared axis doesn't flatten the fast ones to invisible slivers.

    The split point is the mean of each dataset's own average value
    (averaged across parsers) for that operation. This only regroups
    datasets by their own magnitude for legibility -- it does not compare
    parsers against each other or compute any derived ranking between them.
    """
    result: dict[str, list[dict]] = {}

    for operation, shaped in shaped_by_operation.items():
        dataset_names = shaped["datasets"]
        series = shaped["series"]

        averages = []
        for i in range(len(dataset_names)):
            values = [series[parser][i] for parser in series if series[parser][i] is not None]
            averages.append(sum(values) / len(values) if values else 0.0)

        overall_mean = sum(averages) / len(averages) if averages else 0.0

        groups = []
        for label, keep in (("faster datasets", lambda avg: avg <= overall_mean), ("slower datasets", lambda avg: avg > overall_mean)):
            indexes = [i for i, avg in enumerate(averages) if keep(avg)]
            if not indexes:
                continue

            groups.append(
                {
                    "label": label,
                    "datasets": [dataset_names[i] for i in indexes],
                    "series": {parser: [series[parser][i] for i in indexes] for parser in series},
                }
            )

        result[operation] = groups

    return result


def _cache_summary(results: list[dict]) -> list[dict]:
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


def generate_html(results: list[dict]) -> str:
    if not results:
        raise ValueError("No benchmark results available.")

    parsers = sorted({result["parser"] for result in results})
    operations = sorted({result["operation"] for result in results})
    multi_parser = len(parsers) > 1

    total_urls = sum(result["urls"] for result in results)
    total_failures = sum(result["failed"] for result in results)
    total_successes = sum(result["successful"] for result in results)

    failure_rate = (
        total_failures / (total_successes + total_failures) * 100
        if total_successes + total_failures
        else 0
    )

    per_parser = _per_parser_summary(results)
    timing_by_operation = _split_by_scale(_grouped_by_operation(results, "microseconds_per_url"))
    cache_rows = _cache_summary(results)

    chart_payload = json.dumps(
        {
            "parsers": parsers,
            "timingByOperation": timing_by_operation,
        }
    )

    summary_rows: list[str] = []
    for row in per_parser:
        summary_rows.append(
            f"""
            <tr>
                <td><code>{esc(row["parser"])}</code></td>
                <td data-sort="{row['urls']}">{row["urls"]:,}</td>
                <td data-sort="{row['successful']}">{row["successful"]:,}</td>
                <td data-sort="{row['failed']}">{row["failed"]:,}</td>
                <td data-sort="{row['success_rate']}">{row["success_rate"]:.2f}%</td>
                <td data-sort="{row['microseconds_per_url']}">{row["microseconds_per_url"]:.4f}</td>
            </tr>
            """
        )

    detail_rows: list[str] = []
    for result in results:
        error_types = result["errors"]["by_type"]

        if error_types:
            error_text = ", ".join(f"{esc(name)}: {count}" for name, count in error_types.items())
        else:
            error_text = "—"

        distribution = result.get("distribution") or {}
        overall = distribution.get("overall")
        accepted = distribution.get("accepted")
        rejected = distribution.get("rejected")

        p95_cell = f"{overall['p95_us']:.4f}" if overall else "—"
        p95_sort = overall["p95_us"] if overall else -1
        accepted_cell = f"{accepted['mean_us']:.4f}" if accepted else "—"
        rejected_cell = f"{rejected['mean_us']:.4f}" if rejected else "—"

        detail_rows.append(
            f"""
            <tr>
                <td><code>{esc(result["parser"])}</code></td>
                <td>{esc(result["dataset"])}</td>
                <td>{esc(result["operation"])}</td>
                <td data-sort="{result['urls']}">{result["urls"]:,}</td>
                <td data-sort="{result['successful']}">{result["successful"]:,}</td>
                <td data-sort="{result['failed']}">{result["failed"]:,}</td>
                <td data-sort="{result['success_rate']}">{result["success_rate"]:.2f}%</td>
                <td data-sort="{result['elapsed_seconds'] * 1000}">{result["elapsed_seconds"] * 1000:.4f}</td>
                <td data-sort="{result['microseconds_per_url']}">{result["microseconds_per_url"]:.4f}</td>
                <td data-sort="{p95_sort}">{p95_cell}</td>
                <td>{accepted_cell}</td>
                <td>{rejected_cell}</td>
                <td>{error_text}</td>
            </tr>
            """
        )

    operation_charts: list[str] = []
    for operation in operations:
        groups = timing_by_operation.get(operation, [])

        for index, group in enumerate(groups):
            heading = esc(operation)
            if len(groups) > 1:
                heading = f"{esc(operation)} — {esc(group['label'])}"

            operation_charts.append(
                f"""
                <div class="panel chart">
                    <h3>{heading}</h3>
                    <div class="chart-body">
                        <canvas id="timing-{esc(operation)}-{index}"></canvas>
                    </div>
                </div>
                """
            )

    comparison_section = ""
    if multi_parser:
        comparison_section = f"""
        <section>
            <h2>Parsers side by side</h2>
            <p class="section-note">
                Raw μs/URL per dataset, one bar per parser, grouped by operation. Datasets are
                split into "faster"/"slower" panels by their own average magnitude so a
                microsecond-scale dataset isn't flattened next to a hundred-microsecond one on
                the same axis -- no ratios or rankings are computed between parsers.
            </p>
            <div class="grid">
                {"".join(operation_charts)}
            </div>
        </section>
        """

    cache_section = ""
    if cache_rows:
        cache_table_rows = "".join(
            f"""
            <tr>
                <td><code>{esc(row["parser"])}</code></td>
                <td>{esc(row["cache"])}</td>
                <td data-sort="{row['hits']}">{row["hits"]:,}</td>
                <td data-sort="{row['misses']}">{row["misses"]:,}</td>
                <td data-sort="{row['hit_rate'] if row['hit_rate'] is not None else -1}">{
                    f"{row['hit_rate']:.1f}%" if row["hit_rate"] is not None else "—"
                }</td>
                <td data-sort="{row['maxsize'] or 0}">{row["maxsize"] if row["maxsize"] is not None else "—"}</td>
            </tr>
            """
            for row in cache_rows
        )

        cache_section = f"""
        <section>
            <h2>Cache hit rates</h2>
            <p class="section-note">
                Summed hit/miss deltas across every benchmark in this run, per internal cache.
                Only parsers exposing a cache introspection hook appear here.
            </p>
            <div class="panel">
            <div class="table-wrapper">
            <table id="cache-table">
            <thead>
            <tr>
                <th data-type="text">Parser</th>
                <th data-type="text">Cache</th>
                <th data-type="num">Hits</th>
                <th data-type="num">Misses</th>
                <th data-type="num">Hit rate</th>
                <th data-type="num">Max size</th>
            </tr>
            </thead>
            <tbody>
            {cache_table_rows}
            </tbody>
            </table>
            </div>
            </div>
        </section>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>URL Parser Benchmark Report</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
:root {{
    --bg: #f8fafc;
    --panel: #ffffff;
    --panel-2: #f1f5f9;
    --border: #e2e8f0;
    --text: #0f172a;
    --muted: #64748b;
    --blue: #2563eb;
    --purple: #7c3aed;
    --green: #059669;
    --red: #dc2626;
    --orange: #d97706;
    --row-hover: rgba(15, 23, 42, .04);
}}

@media (prefers-color-scheme: dark) {{
    :root {{
        --bg: #0f172a;
        --panel: #111827;
        --panel-2: #1e293b;
        --border: #334155;
        --text: #e5e7eb;
        --muted: #94a3b8;
        --blue: #60a5fa;
        --purple: #a78bfa;
        --green: #34d399;
        --red: #f87171;
        --orange: #fb923c;
        --row-hover: rgba(255, 255, 255, .04);
    }}
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 32px;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}}

.container {{
    max-width: 1800px;
    margin: auto;
}}

h1 {{
    font-size: 28px;
    margin-bottom: 4px;
}}

h2 {{
    font-size: 18px;
    margin: 0 0 4px;
}}

h3 {{
    font-size: 14px;
    margin: 0 0 12px;
    color: var(--muted);
}}

.subtitle {{
    color: var(--muted);
    margin-bottom: 28px;
    font-size: 14px;
}}

.section-note {{
    color: var(--muted);
    font-size: 13px;
    margin: 0 0 16px;
}}

section {{
    margin-bottom: 32px;
}}

.cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 28px;
}}

.card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
}}

.card h3 {{
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .02em;
    margin: 0 0 8px;
}}

.card .value {{
    font-size: 26px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
}}

.blue {{ color: var(--blue); }}
.green {{ color: var(--green); }}
.red {{ color: var(--red); }}
.orange {{ color: var(--orange); }}

.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
    gap: 16px;
}}

.panel {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px;
}}

.chart .chart-body {{
    height: 280px;
    position: relative;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    font-variant-numeric: tabular-nums;
}}

th {{
    background: var(--panel-2);
    text-align: left;
    padding: 10px 12px;
    position: sticky;
    top: 0;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
}}

th:hover {{
    color: var(--blue);
}}

th::after {{
    content: "";
    display: inline-block;
    width: 0.8em;
    opacity: .5;
}}

th.sort-asc::after {{
    content: "▲";
}}

th.sort-desc::after {{
    content: "▼";
}}

td {{
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
}}

tr:hover td {{
    background: var(--row-hover);
}}

.table-wrapper {{
    overflow-x: auto;
    max-height: 640px;
}}

code {{
    color: var(--blue);
    font-size: 12px;
}}

footer {{
    margin-top: 28px;
    color: var(--muted);
    font-size: 12px;
}}
</style>
</head>

<body>
<div class="container">

<h1>URL Parser Benchmark Report</h1>

<div class="subtitle">
{esc(", ".join(parsers))} across {len({r["dataset"] for r in results})} dataset(s) and {len(operations)} operation(s).
</div>

<section>
<div class="cards">

<div class="card">
<h3>Parsers</h3>
<div class="value blue">{len(parsers)}</div>
</div>

<div class="card">
<h3>Benchmark Results</h3>
<div class="value">{len(results):,}</div>
</div>

<div class="card">
<h3>URLs Processed</h3>
<div class="value">{total_urls:,}</div>
</div>

<div class="card">
<h3>Successful Operations</h3>
<div class="value green">{total_successes:,}</div>
</div>

<div class="card">
<h3>Failures</h3>
<div class="value red">{total_failures:,}</div>
</div>

<div class="card">
<h3>Failure Rate</h3>
<div class="value orange">{failure_rate:.2f}%</div>
</div>

</div>
</section>

<section>
<h2>Per-parser totals</h2>
<p class="section-note">Summed across every dataset and operation. Click a column to sort.</p>
<div class="panel">
<div class="table-wrapper">
<table id="summary-table">
<thead>
<tr>
<th data-type="text">Parser</th>
<th data-type="num">URLs</th>
<th data-type="num">OK</th>
<th data-type="num">Failures</th>
<th data-type="num">Success</th>
<th data-type="num">μs / URL</th>
</tr>
</thead>
<tbody>
{"".join(summary_rows)}
</tbody>
</table>
</div>
</div>
</section>

{comparison_section}

{cache_section}

<section>
<h2>Detailed results</h2>
<p class="section-note">One row per parser/dataset/operation combination. Click a column to sort.</p>
<div class="panel">
<div class="table-wrapper">
<table id="detail-table">
<thead>
<tr>
<th data-type="text">Parser</th>
<th data-type="text">Dataset</th>
<th data-type="text">Operation</th>
<th data-type="num">URLs</th>
<th data-type="num">OK</th>
<th data-type="num">Failures</th>
<th data-type="num">Success</th>
<th data-type="num">Time ms</th>
<th data-type="num">μs / URL</th>
<th data-type="num">p95 μs</th>
<th data-type="num">Accepted μs</th>
<th data-type="num">Rejected μs</th>
<th data-type="text">Errors</th>
</tr>
</thead>
<tbody>
{"".join(detail_rows)}
</tbody>
</table>
</div>
</div>
</section>

<footer>
Generated {esc(time.strftime("%Y-%m-%d %H:%M:%S"))}.
</footer>

</div>

<script>

const chartPayload = {chart_payload};

function themeColor(name) {{
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}}

const PARSER_COLORS = [
    themeColor("--blue"),
    themeColor("--purple"),
    themeColor("--green"),
    themeColor("--orange"),
    themeColor("--red"),
    "#22d3ee",
];

function colorFor(parser) {{
    const index = chartPayload.parsers.indexOf(parser);
    return PARSER_COLORS[index % PARSER_COLORS.length];
}}

function renderGroupedChart(canvasId, shaped, yLabel) {{
    const canvas = document.getElementById(canvasId);
    if (!canvas || !shaped) return;

    new Chart(canvas, {{
        type: "bar",
        data: {{
            labels: shaped.datasets,
            datasets: Object.entries(shaped.series).map(([parser, values]) => ({{
                label: parser,
                data: values,
                backgroundColor: colorFor(parser),
            }})),
        }},
        options: {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{
                legend: {{ display: chartPayload.parsers.length > 1 }},
            }},
            scales: {{
                y: {{
                    title: {{ display: true, text: yLabel }},
                    beginAtZero: true,
                }},
            }},
        }},
    }});
}}

for (const [operation, groups] of Object.entries(chartPayload.timingByOperation)) {{
    groups.forEach((group, index) => {{
        renderGroupedChart(`timing-${{operation}}-${{index}}`, group, "μs / URL");
    }});
}}

// --- Sortable tables (vanilla, no dependency) ---------------------------

function makeSortable(tableId) {{
    const table = document.getElementById(tableId);
    if (!table) return;

    const headers = table.querySelectorAll("thead th");
    const tbody = table.querySelector("tbody");

    headers.forEach((th, columnIndex) => {{
        th.addEventListener("click", () => {{
            const ascending = !th.classList.contains("sort-asc");

            headers.forEach((other) => other.classList.remove("sort-asc", "sort-desc"));
            th.classList.add(ascending ? "sort-asc" : "sort-desc");

            const isNumeric = th.dataset.type === "num";
            const rows = Array.from(tbody.querySelectorAll("tr"));

            rows.sort((rowA, rowB) => {{
                const cellA = rowA.children[columnIndex];
                const cellB = rowB.children[columnIndex];

                let valueA = cellA.dataset.sort ?? cellA.textContent.trim();
                let valueB = cellB.dataset.sort ?? cellB.textContent.trim();

                if (isNumeric) {{
                    valueA = parseFloat(valueA) || 0;
                    valueB = parseFloat(valueB) || 0;
                    return ascending ? valueA - valueB : valueB - valueA;
                }}

                return ascending
                    ? String(valueA).localeCompare(String(valueB))
                    : String(valueB).localeCompare(String(valueA));
            }});

            rows.forEach((row) => tbody.appendChild(row));
        }});
    }});
}}

makeSortable("summary-table");
makeSortable("detail-table");
makeSortable("cache-table");

// A live theme switch changes the chart colors read above; reload to
// re-render with the new palette rather than trying to patch charts in place.
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => location.reload());

</script>

</body>
</html>
"""
