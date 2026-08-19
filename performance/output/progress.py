"""
Live console stream for one `benchmark` run.

One line per (parser, dataset, operation) step, prefixed with a running
"[step/total]" counter and a pass/fail glyph -- everything worth glancing
at while the suite runs (where you are, what ran, how it went) lives in
that single line, instead of a parser banner + dataset header + result
line + a possible error line + a possible "dataset adjusted" line for
every step. Per-step error detail and dataset-size history are still
there, just folded into the row itself (the FAIL count, the N column)
rather than interrupting the stream -- the full error breakdown is still
in the end-of-run summary.
"""

from __future__ import annotations

from ..benchmark_suite import BenchmarkResult
from .layout import Column, banner, format_row
from .layout import bar as render_bar
from .theme import CHECK, CROSS, LIGHT_RULE, Ansi, bad, heading, muted, ok, style, warn


def print_suite_header() -> None:
    banner("URL PARSER PERFORMANCE SUITE")


_ROW_COLUMNS = [
    Column("Operation", 18),
    Column("ms", 10, ">"),
    Column("us/url", 10, ">"),
    Column("p95 us", 10, ">"),
    Column("n", 8, ">"),
    Column("OK", 8, ">"),
    Column("FAIL", 8, ">"),
]

# Width of the "glyph + space" gutter printed before every row (see
# result()) -- shared with print_header() so headers line up under it.
_GUTTER_WIDTH = 2


class LiveProgress:
    """
    Stateful reporter for one `benchmark` run's live console stream.

    Construct once per run with the totals known before `run_suite()`
    starts (`cli.py` already has the adapter/dataset/operation lists), then
    pass its bound methods as `run_suite()`'s `on_*` callbacks. All
    counting and formatting lives here -- the engine only ever calls
    plain callables with the data it already has.
    """

    def __init__(self, *, total_parsers: int, total_steps: int) -> None:
        self.total_parsers = total_parsers
        self.total_steps = total_steps

        self._step = 0
        self._step_width = len(str(max(total_steps, 1)))
        self._parser_index = 0

    def print_header(self) -> None:
        indent = " " * (len(self._prefix(0)) + _GUTTER_WIDTH)
        header_row = format_row([c.header for c in _ROW_COLUMNS], _ROW_COLUMNS)

        print(f"\n  {indent}{style(header_row, Ansi.BOLD)}")
        print(f"  {indent}{muted(LIGHT_RULE * len(header_row))}")

    def parser_started(self, name: str) -> None:
        self._parser_index += 1
        label = f" {name} ({self._parser_index}/{self.total_parsers}) "
        print(f"\n{heading(f'{label:{LIGHT_RULE}^88}')}")

    def dataset_started(self, name: str, size: int, *, tunable: bool = False) -> None:
        note = f"  {warn('(auto-tuning)')}" if tunable else ""
        print(f"\n  {render_bar(self._step / self.total_steps if self.total_steps else 1.0)}  "
              f"{style(name, Ansi.BOLD)} ({size:,} URLs){note}")

    def operation_started(self, operation: str) -> None:
        # The row prints all at once from result() -- nothing to show yet.
        pass

    def result(self, result: BenchmarkResult) -> None:
        self._step += 1

        overall = result.distribution.get("overall") if result.distribution else None
        p95_text = f"{overall['p95_us']:.1f}" if overall else "n/a"

        row = format_row(
            [
                result.operation,
                f"{result.elapsed_seconds * 1000:.3f}",
                f"{result.microseconds_per_url:.3f}",
                p95_text,
                f"{result.urls:,}",
                f"{result.successful:,}",
                f"{result.failed:,}",
            ],
            _ROW_COLUMNS,
        )

        glyph = ok(CHECK) if result.failed == 0 else bad(CROSS)
        prefix = muted(self._prefix(self._step))

        print(f"  {prefix}{glyph} {row}")

    def _prefix(self, step: int) -> str:
        return f"[{step:>{self._step_width}}/{self.total_steps}] "
