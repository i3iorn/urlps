"""Control characters are rejected anywhere in a URL -- C1 included.

The check covered C0 (\x00-\x1f) and DEL but not C1 (\x80-\x9f), so a URL
could carry the 8-bit CSI \x9b that some terminals interpret as an escape
sequence introducer.
"""

from __future__ import annotations

import pytest

from urlps import URLParseError, parse_url


@pytest.mark.parametrize("char", ["\x00", "\x1b", "\x7f", "\x80", "\x85", "\x9b", "\x9f"])
@pytest.mark.parametrize(
    "template", ["https://example.com/a{}b", "https://example.com/?q={}", "https://example.com/#f{}"]
)
def test_control_characters_are_rejected(char: str, template: str) -> None:
    with pytest.raises(URLParseError, match="control characters"):
        parse_url(template.format(char))


@pytest.mark.parametrize("char", ["\xa1", "é", "例"])
def test_printable_non_ascii_is_still_accepted(char: str) -> None:
    assert parse_url(f"https://example.com/?q={char}").query == f"q={char}"
