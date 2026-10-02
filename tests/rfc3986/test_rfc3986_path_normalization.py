"""One RFC 3986 dot-segment algorithm for the parser, the builder and join() (B5).

There used to be four implementations, and they disagreed: the parser and
the builder collapsed empty segments ("/a//b" -> "/a/b") and dropped the
trailing slash "/a/b/.." leaves, neither of which RFC 3986 does.
"""

from __future__ import annotations

import pytest

from urlps import InvalidURLError, join, parse_url, parse_url_local
from urlps._builder import Builder
from urlps._parser import Parser, normalize_path
from urlps._resolve import normalize_dot_segments, remove_dot_segments

CASES = [
    ("/a//b", "/a//b"),
    ("//a///b", "//a///b"),
    ("/a/b/..", "/a/"),
    ("/a/b/../", "/a/"),
    ("/a/./b/../c/", "/a/c/"),
    ("/..", "/"),
    ("/a/./", "/a/"),
    ("/a/b/.", "/a/b/"),
    ("/a/%2e%2e/b", "/b"),
    ("/a/%2E/b", "/a/b"),
    ("/a/%2Fb", "/a/%2Fb"),
]


@pytest.mark.parametrize(("path", "expected"), CASES)
def test_parser_builder_and_resolution_agree(path: str, expected: str) -> None:
    assert normalize_path(path) == expected
    assert Builder().normalize_path(path) == expected
    if "%" not in path:
        assert remove_dot_segments(path) == expected
    url = parse_url_local(f"http://example.com{path}")
    assert url.path == expected
    assert parse_url_local(str(url)).path == expected


@pytest.mark.parametrize(("path", "expected"), [("a/..", ""), ("../x", "x"), ("a/b/..", "a/"), ("a//b", "a//b")])
def test_relative_paths_stay_relative(path: str, expected: str) -> None:
    assert normalize_dot_segments(path) == expected


def test_join_result_is_not_renormalized_differently() -> None:
    assert join("https://example.com/a/b/c", "..", policy="local").path == "/a/"
    assert join("https://example.com/x//y/", "z", policy="local").path == "/x//y/z"


def test_unreserved_escapes_are_decoded_before_dot_segments() -> None:
    """%2E%2E is the ".." it denotes; storing "/a/../b" while str() said "/b" is gone."""
    url = parse_url_local("http://example.com/a/%2e%2e/b")
    assert url.path == "/b"
    assert str(url) == "http://example.com/b"


@pytest.mark.parametrize("raw", ["https://good.example/.//evil.example/x", "https://good.example/%2e//evil.example"])
def test_a_path_that_normalizes_to_a_protocol_relative_one_is_an_open_redirect(raw: str) -> None:
    """Keeping "//" means "/.//evil" now normalizes to "//evil"; the check sees the parsed path."""
    with pytest.raises(InvalidURLError) as excinfo:
        parse_url(raw)
    assert excinfo.value.code.value == "open_redirect"


def test_derived_path_that_normalizes_to_protocol_relative_is_rejected_too() -> None:
    with pytest.raises(InvalidURLError):
        parse_url("https://good.example/").with_path("/.//evil.example")


def test_hostless_path_starting_with_two_slashes_is_not_read_back_as_an_authority() -> None:
    composed = Builder().compose({"path": "//not-a-host/x"})
    assert composed == "/.//not-a-host/x"
    parsed = Parser().parse(composed)
    assert parsed["host"] is None
    assert parsed["path"] == "//not-a-host/x"
