"""
Layout primitives: banners, rules, tables, progress bars.

Every banner/table in this module is built from these building blocks, so
a formatting tweak (a rule character, a header style) only has to change
in one place instead of in every print_* function.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from .theme import (
    BAR_EMPTY,
    BAR_FULL,
    BULLET,
    CROSS,
    HEAVY_RULE,
    LIGHT_RULE,
    Ansi,
    bad,
    heading,
    muted,
    style,
)


def rule(*, width: int = 80, char: str = HEAVY_RULE) -> None:
    print(muted(char * width))


def banner(title: str, *, width: int = 80, char: str = HEAVY_RULE) -> None:
    """A blank line, a rule, the bolded title, and a matching rule."""
    print()
    rule(width=width, char=char)
    print(heading(title))
    rule(width=width, char=char)


def section(title: str) -> None:
    """A blank-line-prefixed section heading, e.g. "\nERROR SUMMARY"."""
    print(f"\n{heading(title)}")


def named_list(title: str, items: list[str]) -> None:
    """"\nTitle:" followed by one "  BULLET item" line per item."""
    print(f"\n{style(title + ':', Ansi.BOLD)}")
    for item in items:
        print(f"  {muted(BULLET)} {item}")


def error(message: str) -> None:
    print(f"{bad(CROSS + ' ERROR')}: {message}", file=sys.stderr)


@dataclass(frozen=True)
class Column:
    """One column of a print_table() table: header text, width, alignment."""

    header: str
    width: int
    align: str = "<"  # "<" left, ">" right, "^" center


def format_row(values: list[str], columns: list[Column]) -> str:
    return "".join(
        f"{value:{column.align}{column.width}}"
        for value, column in zip(values, columns)
    )


def print_table(
    columns: list[Column],
    rows: list[list[str]],
    *,
    rule_char: str = LIGHT_RULE,
) -> None:
    """
    Print a bolded header row, a matching-width dim rule, then one row per
    entry in `rows`. Cells are already-formatted strings -- this only
    handles column alignment/width, not numeric formatting or per-cell
    color, so any table (timings, memory, cache hit rates, concurrency,
    compare) can share it and pick up the same look for free.
    """
    header_row = format_row([c.header for c in columns], columns)

    print(style(header_row, Ansi.BOLD))
    print(muted(rule_char * len(header_row)))

    for row in rows:
        print(format_row(row, columns))


def bar(fraction: float, *, width: int = 24) -> str:
    """A `[███████░░░] 62.5%` progress bar, clamped to [0, 1]."""
    fraction = max(0.0, min(1.0, fraction))
    filled = round(fraction * width)

    filled_text = style(BAR_FULL * filled, Ansi.CYAN)
    empty_text = muted(BAR_EMPTY * (width - filled))

    return f"[{filled_text}{empty_text}] {fraction * 100:5.1f}%"
