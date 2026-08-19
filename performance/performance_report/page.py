"""
Top-level report assembly: aggregate the raw results, build each tab, and
wrap them in the page skeleton (head/tabs/script).
"""

from __future__ import annotations

import json
import statistics
import time

from . import aggregate
from ._io import esc
from .components import tab_button, tab_panel
from .css import CSS
from .js import SCRIPT
from .tabs import (
    build_cache_tab,
    build_correctness_tab,
    build_distribution_tab,
    build_errors_tab,
    build_memory_tab,
    build_overview_tab,
    build_raw_data_tab,
    build_security_tab,
    build_timing_tab,
)


def generate_html(results: list[dict]) -> str:
    if not results:
        raise ValueError("No benchmark results available.")

    parsers = sorted({result["parser"] for result in results})
    operations = sorted({result["operation"] for result in results})

    total_urls = sum(result["urls"] for result in results)
    total_failures = sum(result["failed"] for result in results)
    total_successes = sum(result["successful"] for result in results)

    failure_rate = (
        total_failures / (total_successes + total_failures) * 100
        if total_successes + total_failures
        else 0
    )

    per_parser = aggregate.per_parser_summary(results)
    timing_rows = aggregate.timing_rows(results)
    distribution_rows = aggregate.distribution_rows(results)
    error_rows = aggregate.error_summary_rows(results)
    top_errors = aggregate.top_error_types(results)
    timing_by_operation = aggregate.grouped_by_operation(results, "microseconds_per_url")
    throughput_by_operation = aggregate.grouped_by_operation(results, "parses_per_second")
    relative_speed_rows = aggregate.relative_speed_rows(results)
    cache_rows = aggregate.cache_summary(results)
    memory_rows = aggregate.memory_summary(results)
    security_rows = aggregate.security_summary_rows(results)
    security_error_rows = aggregate.security_error_rows(results)
    correctness_rows = aggregate.expectation_accuracy_rows(results)
    correctness_detail_rows = aggregate.expectation_accuracy_detail_rows(results)

    peak_throughput = max((row["parses_per_second"] for row in per_parser), default=0.0)
    typical_p95 = statistics.median([row["p95_us"] for row in distribution_rows]) if distribution_rows else None
    peak_memory_kb = max((row["peak_bytes"] for row in memory_rows), default=0.0) / 1024 if memory_rows else None

    chart_payload = json.dumps(
        {
            "parsers": parsers,
            "timingByOperation": timing_by_operation,
            "throughputByOperation": throughput_by_operation,
            "topErrors": top_errors,
            "memoryByParserOp": [
                {"label": f"{row['parser']} / {row['operation']}", "value": row["peak_bytes"] / 1024}
                for row in sorted(memory_rows, key=lambda r: r["peak_bytes"], reverse=True)[:12]
            ],
            "securityByParser": [
                {"label": row["parser"], "value": row["rejection_rate"]} for row in security_rows
            ],
            "correctnessByParser": sorted(
                (
                    {"label": row["parser"], "value": row["accuracy_pct"]}
                    for row in correctness_rows
                    if row["expectation"] == "invalid"
                ),
                key=lambda row: row["value"],
                reverse=True,
            ),
        }
    )

    overview_tab = build_overview_tab(
        per_parser=per_parser,
        total_results=len(results),
        total_urls=total_urls,
        total_successes=total_successes,
        total_failures=total_failures,
        failure_rate=failure_rate,
        peak_throughput=peak_throughput,
        typical_p95=typical_p95,
        peak_memory_kb=peak_memory_kb,
    )
    timing_tab = build_timing_tab(
        operations=operations,
        timing_by_operation=timing_by_operation,
        throughput_by_operation=throughput_by_operation,
        timing_rows=timing_rows,
        relative_speed_rows=relative_speed_rows,
    )
    distribution_tab = build_distribution_tab(distribution_rows)
    errors_tab = build_errors_tab(error_rows)
    memory_tab = build_memory_tab(memory_rows)
    cache_tab = build_cache_tab(cache_rows)
    security_tab = build_security_tab(security_rows=security_rows, security_error_rows=security_error_rows)
    correctness_tab = build_correctness_tab(accuracy_rows=correctness_rows, detail_rows=correctness_detail_rows)

    tabs: list[tuple[str, str, str]] = [("overview", "Overview", overview_tab), ("timing", "Timing", timing_tab)]

    if distribution_rows:
        tabs.append(("distribution", "Distribution", distribution_tab))

    tabs.append(("errors", "Errors", errors_tab))

    if memory_rows:
        tabs.append(("memory", "Memory", memory_tab))

    if cache_rows:
        tabs.append(("cache", "Cache", cache_tab))

    if security_rows:
        tabs.append(("security", "Security", security_tab))

    if correctness_rows:
        tabs.append(("correctness", "Correctness", correctness_tab))

    tabs.append(("raw", "Raw Data", build_raw_data_tab(results)))

    tab_buttons = "".join(tab_button(tab_id, label, active=(i == 0)) for i, (tab_id, label, _) in enumerate(tabs))
    tab_panels = "".join(tab_panel(tab_id, content, active=(i == 0)) for i, (tab_id, _, content) in enumerate(tabs))

    script = SCRIPT.format(chart_payload=chart_payload)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>URL Parser Benchmark Report</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
{CSS}
</style>
</head>

<body>
<div class="container">

<h1>URL Parser Benchmark Report</h1>

<div class="subtitle">
{esc(", ".join(parsers))} across {len({r["dataset"] for r in results})} dataset(s) and {len(operations)} operation(s).
Generated {esc(time.strftime("%Y-%m-%d %H:%M:%S"))}.
</div>

<div class="tabs">
{tab_buttons}
</div>

{tab_panels}

</div>

<script>
{script}
</script>

</body>
</html>
"""
