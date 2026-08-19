"""Stylesheet for the HTML report -- light/dark theme via CSS variables."""

from __future__ import annotations

CSS = """
:root {
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
}

@media (prefers-color-scheme: dark) {
    :root {
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
    }
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 32px;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

.container {
    max-width: 1800px;
    margin: auto;
}

h1 {
    font-size: 28px;
    margin-bottom: 4px;
}

h2 {
    font-size: 18px;
    margin: 0 0 4px;
}

h3 {
    font-size: 14px;
    margin: 0 0 12px;
    color: var(--muted);
}

.subtitle {
    color: var(--muted);
    margin-bottom: 20px;
    font-size: 14px;
}

.section-note {
    color: var(--muted);
    font-size: 13px;
    margin: 0 0 16px;
}

.empty-state {
    color: var(--muted);
    font-size: 14px;
    padding: 24px 0;
}

section {
    margin-bottom: 32px;
}

/* --- Tabs ------------------------------------------------------------- */

.tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 24px;
    position: sticky;
    top: 0;
    background: var(--bg);
    padding-top: 4px;
    z-index: 10;
}

.tab-btn {
    appearance: none;
    border: none;
    background: transparent;
    color: var(--muted);
    font: inherit;
    font-size: 14px;
    font-weight: 600;
    padding: 10px 16px;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    border-radius: 6px 6px 0 0;
}

.tab-btn:hover {
    color: var(--text);
    background: var(--panel-2);
}

.tab-btn.active {
    color: var(--blue);
    border-bottom-color: var(--blue);
}

.tab-panel.hidden {
    display: none;
}

/* --- Cards -------------------------------------------------------------- */

.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 28px;
}

.card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
}

.card h3 {
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .02em;
    margin: 0 0 8px;
}

.card .value {
    font-size: 26px;
    font-weight: 700;
    font-variant-numeric: tabular-nums;
}

.blue { color: var(--blue); }
.green { color: var(--green); }
.red { color: var(--red); }
.orange { color: var(--orange); }
.purple { color: var(--purple); }

/* --- Charts / grid -------------------------------------------------------- */

.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
    gap: 16px;
}

.panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px;
}

.chart .chart-body {
    height: 280px;
    position: relative;
}

/* Timing/throughput charts get more room -- one dataset-per-bar-group can
   get crowded at the default chart size once several parsers are toggled
   on at once. */
.grid-timing {
    grid-template-columns: repeat(auto-fit, minmax(680px, 1fr));
}

.grid-timing .chart-body {
    height: 560px;
}

/* --- Dataset toggles (per-chart checkboxes) ------------------------------- */

.dataset-toggles {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 12px;
    margin: 4px 0 14px;
    font-size: 12px;
    color: var(--muted);
}

.dataset-toggle {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
}

.dataset-toggle input {
    cursor: pointer;
}

.dataset-toggle-actions {
    display: inline-flex;
    gap: 8px;
    padding-right: 4px;
    border-right: 1px solid var(--border);
    margin-right: 4px;
}

.dataset-toggle-actions button {
    appearance: none;
    border: none;
    background: none;
    color: var(--blue);
    font: inherit;
    font-size: 12px;
    cursor: pointer;
    padding: 0;
    text-decoration: underline;
}

/* --- Pills (quick-jump nav) ---------------------------------------------- */

.pill-row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-bottom: 16px;
}

.pill {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 999px;
    background: var(--panel-2);
    border: 1px solid var(--border);
    color: var(--muted);
    font-size: 12px;
    text-decoration: none;
}

.pill:hover {
    color: var(--blue);
    border-color: var(--blue);
}

/* --- Tables --------------------------------------------------------------- */

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    font-variant-numeric: tabular-nums;
}

th {
    background: var(--panel-2);
    text-align: left;
    padding: 10px 12px;
    position: sticky;
    top: 0;
    cursor: pointer;
    user-select: none;
    white-space: nowrap;
}

th:hover {
    color: var(--blue);
}

th::after {
    content: "";
    display: inline-block;
    width: 0.8em;
    opacity: .5;
}

th.sort-asc::after {
    content: "\\25B2";
}

th.sort-desc::after {
    content: "\\25BC";
}

td {
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
}

tr:hover td {
    background: var(--row-hover);
}

.table-wrapper {
    overflow-x: auto;
    max-height: 640px;
}

code {
    color: var(--blue);
    font-size: 12px;
}

.search-box {
    width: 100%;
    max-width: 420px;
    padding: 8px 12px;
    margin-bottom: 12px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--panel);
    color: var(--text);
    font: inherit;
    font-size: 13px;
}

.search-box:focus {
    outline: none;
    border-color: var(--blue);
}

/* --- Inline ratio bar ------------------------------------------------------ */

.ratio-bar {
    display: inline-block;
    width: 60px;
    height: 6px;
    border-radius: 3px;
    background: var(--panel-2);
    overflow: hidden;
    vertical-align: middle;
    margin-left: 6px;
}

.ratio-fill {
    display: block;
    height: 100%;
}

.ratio-fill.green { background: var(--green); }
.ratio-fill.orange { background: var(--orange); }
.ratio-fill.red { background: var(--red); }

footer {
    margin-top: 28px;
    color: var(--muted);
    font-size: 12px;
}
"""
