"""
Generate an interactive HTML dashboard from benchmark_results.json.

The report is a single self-contained HTML file, organized into tabs
(Overview / Timing / Distribution / Errors / Memory / Cache / Security /
Raw Data) rather than one long scrolling page -- each tab stays focused on
one kind of question ("how fast", "how consistent", "what broke", "how much
memory", "how safe") instead of every table and chart competing for
attention at once.

Split into:

- `_io.py` -- loading results, HTML-escaping, path constants
- `aggregate.py` -- reshaping/summing raw result rows (no derived rankings)
- `components.py` -- small reusable HTML snippets (cards, tables, tabs)
- `tabs.py` -- building each tab's content from aggregated rows
- `css.py` / `js.py` -- the page's stylesheet and client-side script
- `page.py` -- `generate_html()`, the top-level orchestrator
"""

from __future__ import annotations

from ._io import load_results
from .page import generate_html

__all__ = ["generate_html", "load_results"]
