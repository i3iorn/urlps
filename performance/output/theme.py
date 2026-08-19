"""
Terminal styling: color, symbols, box-drawing -- with clean degradation.

Color and Unicode symbols make the output easier to scan, but only when the
terminal actually supports them -- so both degrade automatically: NO_COLOR
/ a non-tty stdout (redirected to a file, piped, CI logs) turns color off;
a non-UTF-8 stdout encoding falls back to plain ASCII glyphs. Same approach
as ripgrep/cargo/eslint, so it behaves the way developers already expect
from a modern CLI tool.
"""

from __future__ import annotations

import os
import sys


def _enable_windows_ansi() -> None:
    """Turn on ANSI escape processing in legacy Windows consoles (conhost)."""
    if sys.platform != "win32":
        return

    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE

        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass  # Best-effort -- worst case, color silently doesn't render.


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True

    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _unicode_enabled() -> bool:
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower().replace("-", "")
    return encoding == "utf8"


_enable_windows_ansi()

COLOR = _color_enabled()
UNICODE = _unicode_enabled()


class Ansi:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN = "\x1b[36m"


def style(text: str, *codes: str) -> str:
    """
    Wrap `text` in ANSI codes; a no-op when color is disabled.

    Always apply this *after* any fixed-width padding -- escape codes are
    invisible on screen but still count as characters to Python's `:<N`
    formatting, so padding a pre-colored string misaligns columns.
    """
    if not COLOR or not codes:
        return text
    return f"{''.join(codes)}{text}{Ansi.RESET}"


# Symbols, with an ASCII fallback for non-UTF-8 terminals. Each pair is
# chosen to be the same *visual* width so they drop into fixed-width
# layouts (the LiveProgress status gutter) without disturbing alignment.
CHECK = "✓" if UNICODE else "+"
CROSS = "✗" if UNICODE else "x"
BULLET = "▸" if UNICODE else "-"
ARROW = "→" if UNICODE else "->"

HEAVY_RULE = "═" if UNICODE else "="
LIGHT_RULE = "─" if UNICODE else "-"
BAR_FULL = "█" if UNICODE else "#"
BAR_EMPTY = "░" if UNICODE else "-"


def ok(text: str) -> str:
    return style(text, Ansi.GREEN)


def bad(text: str) -> str:
    return style(text, Ansi.RED)


def warn(text: str) -> str:
    return style(text, Ansi.YELLOW)


def muted(text: str) -> str:
    return style(text, Ansi.DIM)


def heading(text: str) -> str:
    return style(text, Ansi.BOLD, Ansi.CYAN)
