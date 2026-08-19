"""
Output and reporting helpers for the URL parser performance suite.

This package owns *all* presentation and persistence for the CLI:

- terminal styling (color, symbols, box-drawing -- with clean degradation)
  -- `theme.py`
- layout primitives (banners, rules, tables, progress bars) -- `layout.py`
- the live per-step `benchmark` console stream -- `progress.py`
- parser/dataset/category listings -- `listings.py`
- JSON result-file writers -- `persistence.py`
- `concurrency`/`compare` console output -- `concurrency.py`/`compare.py`
- the end-of-run aggregate summary -- `summary.py`
- small one-off command messages -- `commands.py`

Nothing in `benchmark_suite.py` or `cli.py` should call `print()` directly --
route it through a function here instead. That keeps the benchmark engine
importable/testable without a terminal attached, and keeps every format
change (column widths, colors, wording, etc.) in one place.

Every name below is re-exported at the package root, so `from
performance.output import ...` works exactly as it did when this was a
single module -- the split is an internal organization detail, not part of
the public API.
"""

from __future__ import annotations

from .commands import (
    print_complete,
    print_profile_complete,
    print_profile_start,
    print_report_generated,
    print_results_written,
)
from .compare import (
    CompareRow,
    print_compare_exclusive,
    print_compare_footer,
    print_compare_header,
    print_compare_table,
)
from .concurrency import print_concurrency_header, print_concurrency_summary
from .layout import Column, banner, bar, error, named_list, print_table, rule, section
from .listings import print_categories, print_dataset_list, print_parser_availability
from .persistence import save_concurrency_results, save_results
from .progress import LiveProgress, print_suite_header
from .summary import print_summary
from .theme import (
    ARROW,
    BULLET,
    CHECK,
    COLOR,
    CROSS,
    UNICODE,
    Ansi,
    bad,
    heading,
    muted,
    ok,
    style,
    warn,
)

__all__ = [
    "ARROW",
    "BULLET",
    "CHECK",
    "COLOR",
    "CROSS",
    "UNICODE",
    "Ansi",
    "Column",
    "CompareRow",
    "LiveProgress",
    "bad",
    "banner",
    "bar",
    "error",
    "heading",
    "muted",
    "named_list",
    "ok",
    "print_categories",
    "print_compare_exclusive",
    "print_compare_footer",
    "print_compare_header",
    "print_compare_table",
    "print_complete",
    "print_concurrency_header",
    "print_concurrency_summary",
    "print_dataset_list",
    "print_parser_availability",
    "print_profile_complete",
    "print_profile_start",
    "print_report_generated",
    "print_results_written",
    "print_suite_header",
    "print_summary",
    "print_table",
    "rule",
    "save_concurrency_results",
    "save_results",
    "section",
    "style",
    "warn",
]
