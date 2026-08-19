"""
Client-side script for the HTML report: Chart.js rendering, tab
activation, sortable/filterable tables.

`SCRIPT` is a plain (non-f-string) template with a single `{chart_payload}`
placeholder, filled in by `page.py` via `.format()` -- every other brace in
the JS is doubled so `.format()` leaves it alone.
"""

from __future__ import annotations

SCRIPT = """
const chartPayload = {chart_payload};
const renderedCharts = new Set();

function themeColor(name) {{
    return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}}

// Golden-angle hue spacing spreads any number of parsers around the color
// wheel so each one stays visually distinct -- a fixed-size palette would
// start repeating colors once the parser count exceeded it.
const GOLDEN_ANGLE = 137.508;

function colorFor(parser) {{
    const index = chartPayload.parsers.indexOf(parser);
    const hue = (index * GOLDEN_ANGLE) % 360;
    return `hsl(${{hue.toFixed(1)}}deg 70% 55%)`;
}}

// canvasId -> {{ chart, shaped, hidden }} -- `shaped` is the full, unfiltered
// dataset/series data; `hidden` is the set of dataset names currently
// unchecked. Kept around so the dataset-toggle checkboxes can recompute a
// filtered view without re-fetching or re-deriving anything.
const chartRegistry = {{}};

function filterShaped(shaped, hidden) {{
    const indexes = shaped.datasets
        .map((_, index) => index)
        .filter((index) => !hidden.has(shaped.datasets[index]));

    return {{
        labels: indexes.map((index) => shaped.datasets[index]),
        series: Object.fromEntries(
            Object.entries(shaped.series).map(([parser, values]) => [
                parser,
                indexes.map((index) => values[index]),
            ])
        ),
    }};
}}

function renderGroupedChart(canvasId, shaped, yLabel) {{
    const canvas = document.getElementById(canvasId);
    if (!canvas || !shaped) return;

    const filtered = filterShaped(shaped, new Set());

    const chart = new Chart(canvas, {{
        type: "bar",
        data: {{
            labels: filtered.labels,
            datasets: Object.entries(filtered.series).map(([parser, values]) => ({{
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

    chartRegistry[canvasId] = {{ chart, shaped, hidden: new Set() }};
}}

function applyChartFilter(canvasId) {{
    const entry = chartRegistry[canvasId];
    if (!entry) return;

    const filtered = filterShaped(entry.shaped, entry.hidden);
    entry.chart.data.labels = filtered.labels;
    entry.chart.data.datasets.forEach((dataset) => {{
        dataset.data = filtered.series[dataset.label];
    }});
    entry.chart.update();
}}

function toggleChartDataset(canvasId, datasetName, visible) {{
    const entry = chartRegistry[canvasId];
    if (!entry) return;

    if (visible) {{
        entry.hidden.delete(datasetName);
    }} else {{
        entry.hidden.add(datasetName);
    }}

    applyChartFilter(canvasId);
}}

function setAllChartDatasets(canvasId, visible) {{
    const entry = chartRegistry[canvasId];
    if (!entry) return;

    entry.hidden = visible ? new Set() : new Set(entry.shaped.datasets);

    const toggles = document.getElementById(`${{canvasId}}-toggles`);
    if (toggles) {{
        toggles.querySelectorAll('input[type="checkbox"]').forEach((checkbox) => {{
            checkbox.checked = visible;
        }});
    }}

    applyChartFilter(canvasId);
}}

function renderTimingCharts() {{
    for (const [operation, shaped] of Object.entries(chartPayload.timingByOperation)) {{
        renderGroupedChart(`timing-${{operation}}`, shaped, "µs / URL");
    }}

    for (const [operation, shaped] of Object.entries(chartPayload.throughputByOperation)) {{
        renderGroupedChart(`throughput-${{operation}}`, shaped, "parses / sec");
    }}
}}

function renderErrorChart() {{
    const canvas = document.getElementById("error-chart");
    if (!canvas || !chartPayload.topErrors.length) return;

    new Chart(canvas, {{
        type: "bar",
        data: {{
            labels: chartPayload.topErrors.map(([label]) => label),
            datasets: [{{
                data: chartPayload.topErrors.map(([, value]) => value),
                backgroundColor: themeColor("--red"),
            }}],
        }},
        options: {{
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{ x: {{ title: {{ display: true, text: "Count" }}, beginAtZero: true }} }},
        }},
    }});
}}

function renderMemoryChart() {{
    const canvas = document.getElementById("memory-chart");
    if (!canvas || !chartPayload.memoryByParserOp.length) return;

    new Chart(canvas, {{
        type: "bar",
        data: {{
            labels: chartPayload.memoryByParserOp.map((row) => row.label),
            datasets: [{{
                data: chartPayload.memoryByParserOp.map((row) => row.value),
                backgroundColor: themeColor("--purple"),
            }}],
        }},
        options: {{
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{ x: {{ title: {{ display: true, text: "Peak KB" }}, beginAtZero: true }} }},
        }},
    }});
}}

function renderSecurityChart() {{
    const canvas = document.getElementById("security-chart");
    if (!canvas || !chartPayload.securityByParser.length) return;

    new Chart(canvas, {{
        type: "bar",
        data: {{
            labels: chartPayload.securityByParser.map((row) => row.label),
            datasets: [{{
                data: chartPayload.securityByParser.map((row) => row.value),
                backgroundColor: chartPayload.securityByParser.map((row) => colorFor(row.label)),
            }}],
        }},
        options: {{
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{
                x: {{
                    title: {{ display: true, text: "Rejection rate (%)" }},
                    beginAtZero: true,
                    max: 100,
                }},
            }},
        }},
    }});
}}

function renderCorrectnessChart() {{
    const canvas = document.getElementById("correctness-chart");
    if (!canvas || !chartPayload.correctnessByParser.length) return;

    new Chart(canvas, {{
        type: "bar",
        data: {{
            labels: chartPayload.correctnessByParser.map((row) => row.label),
            datasets: [{{
                data: chartPayload.correctnessByParser.map((row) => row.value),
                backgroundColor: chartPayload.correctnessByParser.map((row) => colorFor(row.label)),
            }}],
        }},
        options: {{
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{
                x: {{
                    title: {{ display: true, text: "Accuracy rejecting invalid URLs (%)" }},
                    beginAtZero: true,
                    max: 100,
                }},
            }},
        }},
    }});
}}

const LAZY_CHART_RENDERERS = {{
    timing: renderTimingCharts,
    errors: renderErrorChart,
    memory: renderMemoryChart,
    security: renderSecurityChart,
    correctness: renderCorrectnessChart,
}};

// --- Tabs -----------------------------------------------------------------

function activateTab(tabId) {{
    document.querySelectorAll(".tab-btn").forEach((btn) => {{
        btn.classList.toggle("active", btn.dataset.tab === tabId);
    }});

    document.querySelectorAll(".tab-panel").forEach((panel) => {{
        panel.classList.toggle("hidden", panel.id !== `tab-${{tabId}}`);
    }});

    // Chart.js needs a visible (non-`display:none`) canvas to size itself
    // correctly, so charts are created the first time their tab opens
    // rather than eagerly at page load, when most tabs are still hidden.
    const renderer = LAZY_CHART_RENDERERS[tabId];
    if (renderer && !renderedCharts.has(tabId)) {{
        renderedCharts.add(tabId);
        renderer();
    }}
}}

const initialTab = document.querySelector(".tab-btn.active");
if (initialTab) activateTab(initialTab.dataset.tab);

// --- Sortable tables (vanilla, no dependency) ------------------------------

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

// --- Filterable tables ------------------------------------------------------

function filterTable(tableId, query) {{
    const table = document.getElementById(tableId);
    if (!table) return;

    const needle = query.trim().toLowerCase();
    const rows = table.querySelectorAll("tbody tr");

    rows.forEach((row) => {{
        const haystack = row.textContent.toLowerCase();
        row.style.display = haystack.includes(needle) ? "" : "none";
    }});
}}

[
    "summary-table", "timing-table", "speed-table", "distribution-table", "error-table",
    "memory-table", "cache-table", "security-table", "security-error-table",
    "correctness-table", "correctness-detail-table", "detail-table",
].forEach(makeSortable);

// A live theme switch changes the chart colors read above; reload to
// re-render with the new palette rather than trying to patch charts in place.
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => location.reload());
"""
