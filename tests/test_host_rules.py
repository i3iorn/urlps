"""The shared host/port rules every layer now uses (``urlps._host`` and ``canonical_host``)."""

from __future__ import annotations

import pytest

from urlps import InvalidURLError, PortValidationError, SecurityPolicy, parse_url
from urlps._builder import Builder, decode_query_pairs
from urlps._helpers import _normalize_port
from urlps._host import ip_literal_text, is_ascii_digits, looks_like_ipv4, port_number, strip_brackets
from urlps._parser import parse_port
from urlps._unicode import IdnaError, canonical_host
from urlps._validation import Validator
from urlps.exceptions import QueryParsingError, URLBuildError


@pytest.mark.parametrize(
    ("host", "bare", "literal"),
    [
        ("[::1]", "::1", "::1"),
        ("[fe80::1%25eth0]", "fe80::1%25eth0", "fe80::1"),
        ("example.com", "example.com", "example.com"),
        ("[unclosed", "[unclosed", "[unclosed"),
    ],
)
def test_bracket_helpers(host: str, bare: str, literal: str) -> None:
    assert strip_brackets(host) == bare
    assert ip_literal_text(host) == literal


@pytest.mark.parametrize(
    ("host", "expected"),
    [("1.2.3.4", True), ("1.2.3.999", True), ("10-1.2", True), ("1234", False), ("a.1.2.3", False)],
)
def test_looks_like_ipv4(host: str, expected: bool) -> None:
    assert looks_like_ipv4(host) is expected


@pytest.mark.parametrize("value", [1, 80, 65535, "1", "443", "65535"])
def test_port_number_accepts(value: object) -> None:
    assert port_number(value) == int(value)  # type: ignore[call-overload]


@pytest.mark.parametrize("value", [0, 65536, -1, "0", "65536", "", " 80", "80.0", 80.0, True, None, "\uff12\uff12"])
def test_port_number_rejects(value: object) -> None:
    with pytest.raises(ValueError):
        port_number(value)


def test_ascii_digits_rejects_unicode_digits() -> None:
    assert is_ascii_digits("22")
    assert not is_ascii_digits("\uff12\uff12")  # fullwidth "22": isdigit() is True, int() reads 22
    assert not is_ascii_digits("")


@pytest.mark.parametrize("value", ["\uff12\uff12", True, 22.0, " 22"])
def test_every_port_entry_point_uses_the_same_grammar(value: object) -> None:
    """The parser, the mutation path and the Validator agree on what a port is."""
    assert not Validator.is_valid_port(value)
    with pytest.raises(InvalidURLError):
        _normalize_port(value)
    if isinstance(value, str):
        with pytest.raises(PortValidationError):
            parse_port(value)
    with pytest.raises(InvalidURLError):
        parse_url("https://example.com/").with_port(value)  # type: ignore[arg-type]


def test_canonical_host_matches_the_parser() -> None:
    for spelling in ("EXAMPLE.com.", "M\u00fcnchen.DE", "[0:0::1]", "127\u30020\u30020\u30021"):
        assert (
            canonical_host(spelling)
            == parse_url(f"http://{spelling}/", policy=SecurityPolicy.internal(enforce_ssrf=False)).host
        )


def test_canonical_host_raises_idna_error() -> None:
    # Matched by base class and name: test_idna_fallback reloads uts46, which
    # replaces the IdnaError class object this module imported.
    with pytest.raises(ValueError) as excinfo:
        canonical_host("\u2603" * 300)
    assert type(excinfo.value).__name__ == IdnaError.__name__


def test_query_decoding_is_shared_and_keeps_each_callers_error() -> None:
    assert decode_query_pairs("a=1&flag&b=x+y&&c=", error=QueryParsingError) == [
        ("a", "1"),
        ("flag", None),
        ("b", "x y"),
        ("c", ""),
    ]
    with pytest.raises(QueryParsingError):
        parse_url("https://example.com/?=x")
    with pytest.raises(URLBuildError):
        Builder().parse_query("=x")
