"""Console output for the `compare` command."""

from __future__ import annotations

from dataclasses import dataclass

from .layout import Column, banner, print_table, rule
from .theme import BULLET, LIGHT_RULE, Ansi, bad, muted, ok, style


def print_compare_header(metric: str) -> None:
    banner(f"BENCHMARK COMPARISON  ({metric})", width=100)


@dataclass(frozen=True)
class CompareRow:
    parser: str
    dataset: str
    operation: str
    before: float
    after: float
    pct_change: float
    marker: str  # "!!" regression, "++" improvement, "  " neither


def _compare_marker_color(marker: str) -> str | None:
    if marker.strip() == "!!":
        return Ansi.RED
    if marker.strip() == "++":
        return Ansi.GREEN
    return None


def print_compare_table(rows: list[CompareRow]) -> None:
    columns = [
        Column("Parser", 15),
        Column("Dataset", 16),
        Column("Operation", 20),
        Column("Baseline", 14, ">"),
        Column("Candidate", 14, ">"),
        Column("Change", 12, ">"),
    ]

    table_rows = []
    for row in rows:
        change_text = f"{row.pct_change:+.2f}% {row.marker}"
        color = _compare_marker_color(row.marker)
        if color:
            change_text = style(f"{change_text:>12}", color)

        table_rows.append(
            [
                row.parser,
                row.dataset,
                row.operation,
                f"{row.before:.4f}",
                f"{row.after:.4f}",
                change_text,
            ]
        )

    print_table(columns, table_rows)
    rule(width=100, char=LIGHT_RULE)


def print_compare_footer(regressions: int, improvements: int, threshold: float) -> None:
    regressions_text = bad(f"{regressions}") if regressions else muted("0")
    improvements_text = ok(f"{improvements}") if improvements else muted("0")

    print(f"Regressions (>= {threshold:g}% worse): {regressions_text}")
    print(f"Improvements (>= {threshold:g}% better): {improvements_text}")


def print_compare_exclusive(label: str, keys: list[tuple[str, str, str]]) -> None:
    if not keys:
        return

    print(f"\n{muted(f'Only in {label} ({len(keys)}):')}")
    for key in keys:
        print(f"  {muted(BULLET)} {' / '.join(key)}")
