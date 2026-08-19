"""
Small HTML building blocks.

The tables/tabs/cards used across the report all repeat the same handful
of shapes; these helpers keep each one defined once instead of re-typed
with slightly different markup per section.
"""

from __future__ import annotations

from ._io import esc


def card(title: str, value: str, *, color: str = "") -> str:
    color_class = f" {color}" if color else ""
    return f"""
    <div class="card">
    <h3>{esc(title)}</h3>
    <div class="value{color_class}">{value}</div>
    </div>
    """


def ratio_bar(pct: float, *, color: str = "green") -> str:
    pct = max(0.0, min(100.0, pct))
    return f"""<span class="ratio-bar" title="{pct:.1f}%"><span class="ratio-fill {color}" style="width:{pct:.1f}%"></span></span>"""


def hit_rate_bar_color(pct: float) -> str:
    if pct >= 90.0:
        return "green"
    if pct >= 60.0:
        return "orange"
    return "red"


def jitter_color(pct: float) -> str:
    """Lower spread between repeated timing passes is better -- inverse of hit-rate coloring."""
    if pct <= 15.0:
        return "green"
    if pct <= 50.0:
        return "orange"
    return "red"


def table_section(
    *,
    title: str,
    note: str,
    table_id: str,
    headers: list[tuple[str, str]],
    rows_html: str,
    controls: str = "",
) -> str:
    """`headers` is a list of (label, data-type) pairs; data-type is "text" or "num"."""
    header_cells = "".join(f'<th data-type="{dtype}">{esc(label)}</th>' for label, dtype in headers)

    return f"""
    <section>
    <h2>{esc(title)}</h2>
    <p class="section-note">{note}</p>
    {controls}
    <div class="panel">
    <div class="table-wrapper">
    <table id="{table_id}">
    <thead><tr>{header_cells}</tr></thead>
    <tbody>{rows_html}</tbody>
    </table>
    </div>
    </div>
    </section>
    """


def search_box(table_id: str, placeholder: str) -> str:
    return f"""
    <input
        type="search"
        class="search-box"
        placeholder="{esc(placeholder)}"
        oninput="filterTable('{table_id}', this.value)"
    >
    """


def tab_button(tab_id: str, label: str, *, active: bool) -> str:
    cls = "tab-btn active" if active else "tab-btn"
    return f'<button class="{cls}" data-tab="{tab_id}" onclick="activateTab(\'{tab_id}\')">{esc(label)}</button>'


def tab_panel(tab_id: str, content: str, *, active: bool) -> str:
    cls = "tab-panel" if active else "tab-panel hidden"
    return f'<div class="{cls}" id="tab-{tab_id}">{content}</div>'
