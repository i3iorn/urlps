"""Python object-model contracts a URL must keep.

``a == b`` must imply ``hash(a) == hash(b)`` (otherwise sets and dict keys
silently hold duplicates), and a URL's components must come from its own
parse even when the Parser instance is shared.
"""

from __future__ import annotations

import pytest

from urlps import URL, parse_url
from urlps._parser import Parser


@pytest.mark.parametrize(
    ("left", "right"),
    [
        # Same serialization, different stored port (443 vs None).
        (lambda: parse_url("https://example.com/"), lambda: parse_url("https://example.com/").with_port(None)),
        # with_path() stores the path as given; the string is normalized.
        (
            lambda: parse_url("https://example.com/b", policy="internal"),
            lambda: parse_url("https://example.com/", policy="internal").with_path("/a/../b"),
        ),
    ],
    ids=["default-port-vs-none", "unnormalized-path"],
)
def test_equal_urls_hash_equal(left, right) -> None:
    a, b = left(), right()
    assert a == b
    assert hash(a) == hash(b)
    assert len({a, b}) == 1


def test_url_hashes_like_the_string_it_equals() -> None:
    url = parse_url("https://example.com/p?q=1#f")
    assert url == str(url)
    assert hash(url) == hash(str(url))
    assert {str(url): "hit"}[url] == "hit"


class _ReusedParser(Parser):
    """Simulates another caller using the same Parser before URL reads its state."""

    def parse(self, maybe_url: str) -> dict:
        result = super().parse(maybe_url)
        super().parse("foo+bar://other.example/?stale=1")
        return result


def test_components_come_from_this_parse_not_the_parsers_last_state() -> None:
    parser = _ReusedParser()
    parser.custom_scheme = True
    url = URL("https://example.com/?k=v", parser=parser)
    assert url.query_params == [("k", "v")]
    assert url.recognized_scheme is True
