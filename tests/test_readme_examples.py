"""Every fenced ```python block in README.md must actually run.

This is a permanent regression guard for a bug class already found once: the
README documented `set_audit_callback()` and `set_audit_event_callback()`,
neither of which had ever existed, and both examples raised ImportError. That
was only caught because someone happened to run every block by hand. This
test makes that check automatic instead of relying on a human doing it again.

DNS resolution is mocked at the same level the rest of the suite already
uses (`check_dns_rebinding_detailed`) so the `check_dns=True` examples stay
deterministic and never touch the network, per CONTRIBUTING.md. Mocking only
`socket.getaddrinfo` is not enough: under `policy="strict"` the DNS check
also performs a real TCP connect to verify the peer, which still reaches out
to the network even with resolution mocked.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import patch

import pytest

README_PATH = Path(__file__).parent.parent / "README.md"
PYTHON_BLOCK_RE = re.compile(r"```python\n(.*?)```", re.DOTALL)

# Blocks that document a call raising, as their last statement, with no
# try/except -- a deliberate README brevity pattern, not a bug. Keyed by the
# block's starting line number (kept in sync manually; a mismatch here fails
# loudly below rather than silently passing the wrong block).
_EXPECTED_TO_RAISE: dict[int, type[Exception]] = {}


def _extract_python_blocks() -> list[tuple[int, str]]:
    """Return (line_number, source) for every fenced python block."""
    text = README_PATH.read_text(encoding="utf-8")
    blocks = []
    for match in PYTHON_BLOCK_RE.finditer(text):
        line_number = text.count("\n", 0, match.start()) + 1
        blocks.append((line_number, match.group(1)))
    return blocks


def _populate_expected_raises(blocks: list[tuple[int, str]]) -> None:
    """Locate the two documented-raise blocks by content, not a hardcoded
    line number, so a README edit that shifts line numbers doesn't silently
    stop testing the right block."""
    from urlps.exceptions import InvalidURLError

    for line_number, source in blocks:
        if 'join("https://example.com/a/", "//localhost/admin")' in source:
            _EXPECTED_TO_RAISE[line_number] = InvalidURLError


_BLOCKS = _extract_python_blocks()
_populate_expected_raises(_BLOCKS)

# A safe, deterministic stand-in for check_dns_rebinding_detailed -- the
# function collect_security_findings calls, mocked at the same import path
# the rest of the suite already uses for this (see
# tests/security/test_security_robustness.py).
_DNS_CHECK_PATH = "urlps._security.check_dns_rebinding_detailed"


def test_readme_has_python_examples():
    """A regression guard on the guard: fail loudly if extraction breaks
    silently (e.g. the fence syntax changes) rather than just collecting zero
    blocks and passing trivially."""
    assert len(_BLOCKS) >= 10, (
        f"Expected at least 10 fenced python blocks in README.md, found "
        f"{len(_BLOCKS)}. If the README's code fence style changed, update "
        f"PYTHON_BLOCK_RE; if blocks were removed, lower this floor."
    )


def test_documented_raise_blocks_were_actually_found():
    """If this is empty, _populate_expected_raises's content match broke --
    which would silently turn the raising block below into a false failure
    (or, worse, a false pass if someone also loosens the assertion)."""
    assert _EXPECTED_TO_RAISE, "Expected to find at least one documented-raise README block"


@pytest.mark.parametrize(
    "line_number,source",
    _BLOCKS,
    ids=[f"line_{ln}" for ln, _ in _BLOCKS],
)
def test_readme_example_executes(line_number, source):
    expected_exception = _EXPECTED_TO_RAISE.get(line_number)

    with patch(_DNS_CHECK_PATH, return_value=(True, None)):
        try:
            exec(compile(source, f"<README.md:{line_number}>", "exec"), {"__name__": "__main__"})
        except Exception as exc:
            if expected_exception is not None and isinstance(exc, expected_exception):
                return  # documented, deliberate -- this block is supposed to raise
            raise AssertionError(
                f"README.md example starting at line {line_number} failed: {type(exc).__name__}: {exc}\n\n{source}"
            ) from exc
        else:
            if expected_exception is not None:
                raise AssertionError(
                    f"README.md example at line {line_number} was expected to raise "
                    f"{expected_exception.__name__} (per its own comment) but did not."
                )
