"""
Small one-off console messages: cProfile lifecycle (`profile`) and
file-written/completion messages shared by `benchmark`/`report`/`all`.
"""

from __future__ import annotations

from pathlib import Path

from .layout import banner
from .theme import ARROW, BULLET, CHECK, muted, ok


def print_profile_start(parser: str, dataset: str, operation: str) -> None:
    banner(f"cProfile: {parser} {ARROW} {dataset} {ARROW} {operation}")


def print_profile_complete(profile_path: str | Path, text_path: str | Path) -> None:
    print(f"Raw profile: {profile_path}")
    print(f"Text profile: {text_path}")


def print_results_written(path: str | Path) -> None:
    print(f"\n{ok(CHECK)} Results written to:\n     {Path(path).resolve()}")


def print_report_generated(path: str | Path) -> None:
    print(f"{ok(CHECK)} Generated:\n     {Path(path).resolve()}")


def print_complete(paths: list[str | Path]) -> None:
    banner("COMPLETE")
    print("\nGenerated:")
    for path in paths:
        print(f"  {muted(BULLET)} {Path(path).resolve()}")
