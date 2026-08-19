"""
Building the content of each report tab (Overview / Timing / Distribution /
Errors / Memory / Cache / Raw Data) from already-aggregated rows.
"""

from __future__ import annotations

from ._io import esc, fmt_rate
from .components import card, hit_rate_bar_color, jitter_color, ratio_bar, search_box, table_section


def build_overview_tab(
    *,
    per_parser: list[dict],
    total_results: int,
    total_urls: int,
    total_successes: int,
    total_failures: int,
    failure_rate: float,
    peak_throughput: float,
    typical_p95: float | None,
    peak_memory_kb: float | None,
) -> str:
    overview_cards = [
        card("Parsers", str(len(per_parser)), color="blue"),
        card("Benchmark Results", f"{total_results:,}"),
        card("URLs Processed", f"{total_urls:,}"),
        card("Successful Operations", f"{total_successes:,}", color="green"),
        card("Failures", f"{total_failures:,}", color="red"),
        card("Failure Rate", f"{failure_rate:.2f}%", color="orange"),
        card("Peak Throughput", f"{fmt_rate(peak_throughput)} /s", color="purple"),
    ]

    if typical_p95 is not None:
        overview_cards.append(card("Median P95 Latency", f"{typical_p95:.2f} µs"))

    if peak_memory_kb is not None:
        overview_cards.append(card("Peak Memory", f"{peak_memory_kb:,.1f} KB"))

    summary_rows_html = "".join(
        f"""
        <tr>
            <td><code>{esc(row["parser"])}</code></td>
            <td data-sort="{row['urls']}">{row["urls"]:,}</td>
            <td data-sort="{row['successful']}">{row["successful"]:,}</td>
            <td data-sort="{row['failed']}">{row["failed"]:,}</td>
            <td data-sort="{row['success_rate']}">{row["success_rate"]:.2f}% {ratio_bar(row["success_rate"], color=hit_rate_bar_color(row["success_rate"]))}</td>
            <td data-sort="{row['microseconds_per_url']}">{row["microseconds_per_url"]:.4f}</td>
            <td data-sort="{row['parses_per_second']}">{fmt_rate(row["parses_per_second"])}</td>
        </tr>
        """
        for row in per_parser
    )

    return f"""
    <div class="cards">
    {"".join(overview_cards)}
    </div>

    {table_section(
        title="Per-parser totals",
        note="Summed across every dataset and operation. Click a column to sort.",
        table_id="summary-table",
        headers=[
            ("Parser", "text"), ("URLs", "num"), ("OK", "num"), ("Failures", "num"),
            ("Success", "num"), ("µs / URL", "num"), ("Parses/sec", "num"),
        ],
        rows_html=summary_rows_html,
    )}
    """


def _dataset_toggle_row(canvas_id: str, datasets: list[str]) -> str:
    """
    One checkbox per dataset (x-axis category), checked by default. Parsers
    are already toggleable via the Chart.js legend -- that only hides/shows
    a *series*, not an x-axis category, so datasets need their own control.
    """
    checkboxes = "".join(
        f"""<label class="dataset-toggle">
            <input type="checkbox" checked
                   onchange="toggleChartDataset('{canvas_id}', '{esc(dataset)}', this.checked)">
            {esc(dataset)}
        </label>"""
        for dataset in datasets
    )

    return f"""
    <div class="dataset-toggles" id="{canvas_id}-toggles">
        <span class="dataset-toggle-actions">
            <button type="button" onclick="setAllChartDatasets('{canvas_id}', true)">All</button>
            <button type="button" onclick="setAllChartDatasets('{canvas_id}', false)">None</button>
        </span>
        {checkboxes}
    </div>
    """


def _chart_grid(*, operations: list[str], by_operation: dict[str, dict], id_prefix: str) -> tuple[str, str]:
    """
    Shared chart-grid builder for the timing tab's µs/URL and parses/sec
    sections -- one chart per operation, every dataset on it. Parsers can be
    toggled off via the Chart.js legend; datasets get their own checkbox row
    since Chart.js's legend only controls series, not x-axis categories.
    """
    charts: list[str] = []
    jump_pills: list[str] = []

    for operation in operations:
        shaped = by_operation.get(operation)
        if not shaped:
            continue

        panel_id = f"{id_prefix}-panel-{esc(operation)}"
        canvas_id = f"{id_prefix}-{esc(operation)}"
        heading_text = esc(operation)

        jump_pills.append(f'<a class="pill" href="#{panel_id}">{heading_text}</a>')

        charts.append(
            f"""
            <div class="panel chart" id="{panel_id}">
                <h3>{heading_text}</h3>
                {_dataset_toggle_row(canvas_id, shaped["datasets"])}
                <div class="chart-body">
                    <canvas id="{canvas_id}"></canvas>
                </div>
            </div>
            """
        )

    return "".join(jump_pills), "".join(charts)


def build_timing_tab(
    *,
    operations: list[str],
    timing_by_operation: dict[str, dict],
    throughput_by_operation: dict[str, dict],
    timing_rows: list[dict],
    relative_speed_rows: list[dict],
) -> str:
    timing_pills, timing_charts = _chart_grid(operations=operations, by_operation=timing_by_operation, id_prefix="timing")
    throughput_pills, throughput_charts = _chart_grid(
        operations=operations, by_operation=throughput_by_operation, id_prefix="throughput"
    )

    speed_rows_html = "".join(
        f"""
        <tr>
            <td>{esc(row["operation"])}</td>
            <td><code>{esc(row["parser"])}</code></td>
            <td data-sort="{row['microseconds_per_url']}">{row["microseconds_per_url"]:.4f}</td>
            <td data-sort="{row['relative']}">{"fastest" if row["relative"] <= 1.0 else f"{row['relative']:.2f}x slower"}</td>
        </tr>
        """
        for row in relative_speed_rows
    )

    timing_detail_rows_html = "".join(
        f"""
        <tr>
            <td><code>{esc(row["parser"])}</code></td>
            <td>{esc(row["dataset"])}</td>
            <td>{esc(row["operation"])}</td>
            <td data-sort="{row['urls']}">{row["urls"]:,}</td>
            <td data-sort="{row['successful']}">{row["successful"]:,}</td>
            <td data-sort="{row['failed']}">{row["failed"]:,}</td>
            <td data-sort="{row['success_rate']}">{row["success_rate"]:.2f}%</td>
            <td data-sort="{row['elapsed_ms']}">{row["elapsed_ms"]:.4f}</td>
            <td data-sort="{row['microseconds_per_url']}">{row["microseconds_per_url"]:.4f}</td>
            <td data-sort="{row['parses_per_second']}">{fmt_rate(row["parses_per_second"])}</td>
            <td data-sort="{row['min_ms'] if row['min_ms'] is not None else -1}">{f"{row['min_ms']:.4f}" if row["min_ms"] is not None else "—"}</td>
            <td data-sort="{row['max_ms'] if row['max_ms'] is not None else -1}">{f"{row['max_ms']:.4f}" if row["max_ms"] is not None else "—"}</td>
            <td data-sort="{row['jitter_pct'] if row['jitter_pct'] is not None else -1}">{
                f'{row["jitter_pct"]:.1f}% ' + ratio_bar(min(row["jitter_pct"], 100.0), color=jitter_color(row["jitter_pct"]))
                if row["jitter_pct"] is not None else "—"
            }</td>
        </tr>
        """
        for row in timing_rows
    )

    return f"""
    <p class="section-note">
        Raw µs/URL per dataset, one bar per parser, grouped by operation. Toggle a parser
        off via the chart legend, or a dataset off via the checkboxes above each chart, to
        compare just the ones you care about on a shared axis -- no ratios or rankings are
        computed between parsers here.
    </p>
    <div class="pill-row">{timing_pills}</div>
    <div class="grid grid-timing">
        {timing_charts}
    </div>

    <h2 style="margin-top:28px">Throughput (parses/sec)</h2>
    <p class="section-note">
        Same datasets, inverted to parses/sec -- useful when "higher is better" reads more
        naturally than "lower is better".
    </p>
    <div class="pill-row">{throughput_pills}</div>
    <div class="grid grid-timing">
        {throughput_charts}
    </div>

    {table_section(
        title="Relative speed",
        note="Each parser's URL-weighted mean µs/URL for that operation, compared against the "
             "fastest parser for the same operation. The only ranking the report computes -- "
             "everywhere else parsers are shown side by side, unranked.",
        table_id="speed-table",
        headers=[("Operation", "text"), ("Parser", "text"), ("µs / URL", "num"), ("Relative", "num")],
        rows_html=speed_rows_html,
    )}

    {table_section(
        title="Timing detail",
        note='One row per parser/dataset/operation combination. "Min ms"/"Max ms" are the '
             'fastest/slowest of the repeated timing passes behind the headline number, and '
             '"Jitter" is their spread as a percentage of the mean -- a wide spread means the '
             'measurement was noisy, not necessarily that the parser is.',
        table_id="timing-table",
        headers=[
            ("Parser", "text"), ("Dataset", "text"), ("Operation", "text"), ("URLs", "num"),
            ("OK", "num"), ("Failures", "num"), ("Success", "num"), ("Time ms", "num"),
            ("µs / URL", "num"), ("Parses/sec", "num"), ("Min ms", "num"), ("Max ms", "num"),
            ("Jitter", "num"),
        ],
        rows_html=timing_detail_rows_html,
        controls=search_box("timing-table", "Filter by parser, dataset, or operation…"),
    )}
    """


def build_distribution_tab(distribution_rows: list[dict]) -> str:
    if not distribution_rows:
        return '<p class="empty-state">No latency distribution data in this run.</p>'

    distribution_rows_html = "".join(
        f"""
        <tr>
            <td><code>{esc(row["parser"])}</code></td>
            <td>{esc(row["dataset"])}</td>
            <td>{esc(row["operation"])}</td>
            <td data-sort="{row['count']}">{row["count"]:,}</td>
            <td data-sort="{row['mean_us']}">{row["mean_us"]:.3f}</td>
            <td data-sort="{row['p50_us']}">{row["p50_us"]:.3f}</td>
            <td data-sort="{row['p95_us']}">{row["p95_us"]:.3f}</td>
            <td data-sort="{row['p99_us']}">{row["p99_us"]:.3f}</td>
            <td data-sort="{row['max_us']}">{row["max_us"]:.3f}</td>
            <td data-sort="{row['accepted_mean_us'] if row['accepted_mean_us'] is not None else -1}">{f"{row['accepted_mean_us']:.3f}" if row["accepted_mean_us"] is not None else "—"}</td>
            <td data-sort="{row['rejected_mean_us'] if row['rejected_mean_us'] is not None else -1}">{f"{row['rejected_mean_us']:.3f}" if row["rejected_mean_us"] is not None else "—"}</td>
            <td data-sort="{row['microseconds_per_byte'] if row['microseconds_per_byte'] is not None else -1}">{f"{row['microseconds_per_byte']:.4f}" if row["microseconds_per_byte"] is not None else "—"}</td>
        </tr>
        """
        for row in distribution_rows
    )

    return f"""
    {table_section(
        title="Latency distribution",
        note="Per-URL timing percentiles from a dedicated single pass over every URL "
             "individually (see the README) -- p50/p95/p99/max, plus the accepted-vs-rejected "
             "mean split and per-byte throughput. Comparing accepted vs. rejected latency "
             "shows whether rejecting bad input is cheap or is accidentally the slow path.",
        table_id="distribution-table",
        headers=[
            ("Parser", "text"), ("Dataset", "text"), ("Operation", "text"), ("Count", "num"),
            ("Mean µs", "num"), ("P50 µs", "num"), ("P95 µs", "num"),
            ("P99 µs", "num"), ("Max µs", "num"), ("Accepted µs", "num"),
            ("Rejected µs", "num"), ("µs / byte", "num"),
        ],
        rows_html=distribution_rows_html,
        controls=search_box("distribution-table", "Filter by parser, dataset, or operation…"),
    )}
    """


def build_errors_tab(error_rows: list[dict]) -> str:
    if not error_rows:
        return '<p class="empty-state">✓ No errors recorded in this run.</p>'

    error_rows_html = "".join(
        f"""
        <tr>
            <td><code>{esc(row["parser"])}</code></td>
            <td>{esc(row["operation"])}</td>
            <td>{esc(row["error_type"])}</td>
            <td data-sort="{row['count']}">{row["count"]:,}</td>
        </tr>
        """
        for row in error_rows
    )

    return f"""
    <div class="panel chart">
        <h3>Top error types</h3>
        <div class="chart-body"><canvas id="error-chart"></canvas></div>
    </div>

    {table_section(
        title="Error breakdown",
        note="Every recorded error, summed by parser/operation/error type across all datasets.",
        table_id="error-table",
        headers=[("Parser", "text"), ("Operation", "text"), ("Error type", "text"), ("Count", "num")],
        rows_html=error_rows_html,
        controls=search_box("error-table", "Filter by parser, operation, or error type…"),
    )}
    """


def build_memory_tab(memory_rows: list[dict]) -> str:
    if not memory_rows:
        return ""

    memory_table_rows = "".join(
        f"""
        <tr>
            <td><code>{esc(row["parser"])}</code></td>
            <td>{esc(row["operation"])}</td>
            <td data-sort="{row['peak_bytes'] / 1024}">{row["peak_bytes"] / 1024:,.2f}</td>
            <td data-sort="{row['bytes_per_url']}">{row["bytes_per_url"]:,.2f}</td>
            <td data-sort="{row['object_count']}">{row["object_count"]:,.0f}</td>
        </tr>
        """
        for row in memory_rows
    )

    return f"""
    <div class="panel chart">
        <h3>Peak memory by parser / operation</h3>
        <div class="chart-body"><canvas id="memory-chart"></canvas></div>
    </div>

    {table_section(
        title="Memory",
        note='Per parser+operation, across every dataset in this run. "Peak KB" is the '
             'worst-case high-water mark across datasets (not additive); "Bytes/URL" and '
             '"Objects" are averaged across datasets. Measured via <code>tracemalloc</code>, '
             'so this reflects Python-level allocations only.',
        table_id="memory-table",
        headers=[("Parser", "text"), ("Operation", "text"), ("Peak KB", "num"), ("Bytes/URL", "num"), ("Objects", "num")],
        rows_html=memory_table_rows,
    )}
    """


def build_cache_tab(cache_rows: list[dict]) -> str:
    if not cache_rows:
        return ""

    cache_table_rows = "".join(
        f"""
        <tr>
            <td><code>{esc(row["parser"])}</code></td>
            <td>{esc(row["cache"])}</td>
            <td data-sort="{row['hits']}">{row["hits"]:,}</td>
            <td data-sort="{row['misses']}">{row["misses"]:,}</td>
            <td data-sort="{row['hit_rate'] if row['hit_rate'] is not None else -1}">{
                f"{row['hit_rate']:.1f}% " + ratio_bar(row['hit_rate'], color=hit_rate_bar_color(row['hit_rate']))
                if row["hit_rate"] is not None else "—"
            }</td>
            <td data-sort="{row['maxsize'] or 0}">{row["maxsize"] if row["maxsize"] is not None else "—"}</td>
        </tr>
        """
        for row in cache_rows
    )

    return f"""
    {table_section(
        title="Cache hit rates",
        note="Summed hit/miss deltas across every benchmark in this run, per internal cache. "
             "Only parsers exposing a cache introspection hook appear here.",
        table_id="cache-table",
        headers=[("Parser", "text"), ("Cache", "text"), ("Hits", "num"), ("Misses", "num"), ("Hit rate", "num"), ("Max size", "num")],
        rows_html=cache_table_rows,
    )}
    """


def build_security_tab(*, security_rows: list[dict], security_error_rows: list[dict]) -> str:
    """
    How each parser handles the hand-written malicious/adversarial URL
    corpus (SSRF, path traversal, homograph spoofing, etc. -- see
    url_cases/malicious.py). For this dataset specifically, *rejecting* a
    URL is the good outcome -- the inverse of every other tab's
    success/failure framing -- so it's called out explicitly rather than
    left implicit in a generic error table.
    """
    if not security_rows:
        return '<p class="empty-state">No results for the malicious URL corpus in this run.</p>'

    best = security_rows[0]
    worst = security_rows[-1]

    cards = [
        card("Malicious URLs Tested", f"{security_rows[0]['urls']:,}", color="blue"),
        card("Highest Rejection Rate", f"{best['rejection_rate']:.1f}% ({esc(best['parser'])})", color="green"),
        card("Lowest Rejection Rate", f"{worst['rejection_rate']:.1f}% ({esc(worst['parser'])})", color="red"),
    ]

    summary_rows_html = "".join(
        f"""
        <tr>
            <td><code>{esc(row["parser"])}</code></td>
            <td data-sort="{row['urls']}">{row["urls"]:,}</td>
            <td data-sort="{row['rejected']}">{row["rejected"]:,}</td>
            <td data-sort="{row['accepted']}">{row["accepted"]:,}</td>
            <td data-sort="{row['rejection_rate']}">{row["rejection_rate"]:.2f}% {ratio_bar(row["rejection_rate"], color=hit_rate_bar_color(row["rejection_rate"]))}</td>
        </tr>
        """
        for row in security_rows
    )

    error_rows_html = "".join(
        f"""
        <tr>
            <td><code>{esc(row["parser"])}</code></td>
            <td>{esc(row["error_type"])}</td>
            <td data-sort="{row['count']}">{row["count"]:,}</td>
        </tr>
        """
        for row in security_error_rows
    )

    error_section = (
        table_section(
            title="Rejection reasons",
            note="Which validation error each parser raised when it rejected a malicious URL.",
            table_id="security-error-table",
            headers=[("Parser", "text"), ("Error type", "text"), ("Count", "num")],
            rows_html=error_rows_html,
        )
        if security_error_rows
        else ""
    )

    return f"""
    <p class="section-note">
        Results against the hand-written adversarial URL corpus (SSRF, path traversal,
        homograph spoofing, credential smuggling, and more). Unlike every other tab,
        <strong>rejecting</strong> a URL here is the good outcome -- it means the parser's
        validation caught something dangerous rather than silently returning a value for it.
    </p>

    <div class="cards">
    {"".join(cards)}
    </div>

    <div class="panel chart">
        <h3>Rejection rate by parser</h3>
        <div class="chart-body"><canvas id="security-chart"></canvas></div>
    </div>

    {table_section(
        title="Malicious corpus handling",
        note="Rejected = raised a validation error (good, for this dataset). "
             "Accepted = parsed without complaint (the URL was not flagged).",
        table_id="security-table",
        headers=[
            ("Parser", "text"), ("URLs", "num"), ("Rejected", "num"),
            ("Accepted", "num"), ("Rejection rate", "num"),
        ],
        rows_html=summary_rows_html,
    )}

    {error_section}
    """


_EXPECTATION_LABELS = {
    "valid": "Valid (should accept)",
    "invalid": "Invalid (should reject)",
    "unsafe": "Unsafe (security-tagged parsers should reject)",
    "ambiguous": "Ambiguous",
    "unknown": "Unknown",
}


def build_correctness_tab(*, accuracy_rows: list[dict], detail_rows: list[dict]) -> str:
    """
    Whether each parser's accept/reject verdict matches each URL's *known*
    expected outcome, across every dataset that carries expectation data --
    not just the malicious corpus (see url_cases/_models.py's EXPECTATION_*
    vocabulary and its per-corpus annotations). This is the only place the
    report checks a parser's behavior against a real right answer instead
    of just reporting what happened.
    """
    if not accuracy_rows:
        return '<p class="empty-state">No expectation data in this run (see url_cases/_models.py).</p>'

    invalid_rows = sorted(
        (row for row in accuracy_rows if row["expectation"] == "invalid"),
        key=lambda row: row["accuracy_pct"],
        reverse=True,
    )

    cards = []
    if invalid_rows:
        best, worst = invalid_rows[0], invalid_rows[-1]
        cards = [
            card(
                "Best at rejecting invalid URLs",
                f"{best['accuracy_pct']:.1f}% ({esc(best['parser'])})",
                color="green",
            ),
            card(
                "Worst at rejecting invalid URLs",
                f"{worst['accuracy_pct']:.1f}% ({esc(worst['parser'])})",
                color="red",
            ),
        ]

    summary_rows_html = "".join(
        f"""
        <tr>
            <td><code>{esc(row["parser"])}</code></td>
            <td>{esc(_EXPECTATION_LABELS.get(row["expectation"], row["expectation"]))}</td>
            <td data-sort="{row['total']}">{row["total"]:,}</td>
            <td data-sort="{row['correct']}">{row["correct"]:,}</td>
            <td data-sort="{row['incorrect']}">{row["incorrect"]:,}</td>
            <td data-sort="{row['accuracy_pct']}">{row["accuracy_pct"]:.2f}% {ratio_bar(row["accuracy_pct"], color=hit_rate_bar_color(row["accuracy_pct"]))}</td>
        </tr>
        """
        for row in accuracy_rows
    )

    detail_rows_html = "".join(
        f"""
        <tr>
            <td><code>{esc(row["parser"])}</code></td>
            <td>{esc(row["dataset"])}</td>
            <td>{esc(row["operation"])}</td>
            <td>{esc(_EXPECTATION_LABELS.get(row["expectation"], row["expectation"]))}</td>
            <td data-sort="{row['total']}">{row["total"]:,}</td>
            <td data-sort="{row['correct']}">{row["correct"]:,}</td>
            <td data-sort="{row['accuracy_pct']}">{row["accuracy_pct"]:.2f}%</td>
        </tr>
        """
        for row in detail_rows
    )

    return f"""
    <p class="section-note">
        Whether each parser's accept/reject verdict matches each URL's known expected
        outcome. <strong>Valid</strong> URLs should be accepted; <strong>invalid</strong>
        ones (malformed under any reasonable interpretation) should be rejected;
        <strong>unsafe</strong> ones (syntactically valid, semantically dangerous -- SSRF
        targets, credential smuggling, ...) are only scored for parsers tagged
        "security", since accepting one is not a parsing bug for a plain parser that was
        never asked to judge safety. Ambiguous/unknown URLs are never scored. Note: a
        strict-by-default parser correctly rejecting something outside its own security
        policy (e.g. a loopback/private-IP host, even in an otherwise ordinary dataset)
        will show up as "incorrect" here too -- read this as a lens for investigation,
        not a pass/fail scorecard.
    </p>

    <div class="cards">
    {"".join(cards)}
    </div>

    <div class="panel chart">
        <h3>Accuracy rejecting invalid URLs, by parser</h3>
        <div class="chart-body"><canvas id="correctness-chart"></canvas></div>
    </div>

    {table_section(
        title="Accuracy by expectation bucket",
        note="Summed across every dataset and operation that carries expectation data.",
        table_id="correctness-table",
        headers=[
            ("Parser", "text"), ("Expected outcome", "text"), ("Scored", "num"),
            ("Correct", "num"), ("Incorrect", "num"), ("Accuracy", "num"),
        ],
        rows_html=summary_rows_html,
    )}

    {table_section(
        title="Accuracy detail",
        note="One row per parser/dataset/operation/expectation-bucket combination.",
        table_id="correctness-detail-table",
        headers=[
            ("Parser", "text"), ("Dataset", "text"), ("Operation", "text"),
            ("Expected outcome", "text"), ("Scored", "num"), ("Correct", "num"), ("Accuracy", "num"),
        ],
        rows_html=detail_rows_html,
        controls=search_box("correctness-detail-table", "Filter by parser, dataset, or operation…"),
    )}
    """


def _error_text(result: dict) -> str:
    error_types = result["errors"]["by_type"]
    if not error_types:
        return "—"
    return ", ".join(f"{name}: {count}" for name, count in error_types.items())


def build_raw_data_tab(results: list[dict]) -> str:
    """
    The full, unaggregated result set -- every field, one row per benchmark.
    Kept for power users/debugging; everyone else should find what they need
    in the more focused tabs above.
    """
    rows_html = "".join(
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
            <td>{esc(_error_text(result))}</td>
        </tr>
        """
        for result in results
    )

    return f"""
    {table_section(
        title="Raw results",
        note="Every benchmark result, unaggregated -- one row per parser/dataset/operation "
             "combination. The Timing/Distribution/Errors/Memory/Cache tabs above are this "
             "same data, reshaped around one question each.",
        table_id="detail-table",
        headers=[
            ("Parser", "text"), ("Dataset", "text"), ("Operation", "text"), ("URLs", "num"),
            ("OK", "num"), ("Failures", "num"), ("Success", "num"), ("Time ms", "num"),
            ("µs / URL", "num"), ("Errors", "text"),
        ],
        rows_html=rows_html,
        controls=search_box("detail-table", "Filter by parser, dataset, operation, or error…"),
    )}
    """
