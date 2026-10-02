"""A derived URL is exactly what parsing its own string gives (H1/B3).

copy() and with_*() used to assemble URLs with their own copy of the
parser's normalization; the copies drifted (with_path("/a/../b") kept the
dot segments in .path while str(url) dropped them). Every derivation now
runs through the parser's normalize_components().
"""

from __future__ import annotations

import pytest

from urlps import UnsupportedSchemeError, build, parse_url, parse_url_local

BASE = "https://user:pw@example.com:8443/a/b?q=1&r=2#frag"

DERIVATIONS = {
    "dot-segments-and-escapes": lambda u: u.with_path("/a/../b/%7e"),
    "empty-segments": lambda u: u.with_path("/x//y/."),
    "relative-path": lambda u: u.with_path("c/d"),
    "port-none": lambda u: u.with_port(None),
    "port": lambda u: u.with_port(9000),
    "scheme": lambda u: u.with_scheme("http"),
    "host-case-and-dot": lambda u: u.with_host("EXAMPLE.org."),
    "host-idn": lambda u: u.with_host("München.de"),
    "host-ipv6": lambda u: u.with_host("[0:0::1]"),
    "userinfo-escaped": lambda u: u.with_userinfo("us er:pa ss"),
    "query": lambda u: u.with_query("b=%7e&a=1"),
    "query-pairs-only": lambda u: u.copy(query_pairs=[("z", "1"), ("a", None)]),
    "fragment": lambda u: u.with_fragment("sec%7e"),
    "query-param": lambda u: u.with_query_param("k", "v & w"),
    "without-query-param": lambda u: u.without_query_param("q"),
    "without-query": lambda u: u.without_query(),
    "netloc": lambda u: u.with_netloc("other.example:8080"),
    "canonicalize": lambda u: u.canonicalize(),
}


@pytest.mark.parametrize("derive", DERIVATIONS.values(), ids=DERIVATIONS.keys())
def test_derived_url_equals_parsing_its_own_string(derive) -> None:
    derived = derive(parse_url_local(BASE))
    reparsed = parse_url_local(str(derived))
    assert derived._parts == reparsed._parts
    assert derived == reparsed and hash(derived) == hash(reparsed)


def test_with_path_is_normalized_like_a_parse() -> None:
    url = parse_url("https://example.com/").with_path("/a/../b/%7e")
    assert url.path == "/b/~"
    assert str(url) == "https://example.com/b/~"


def test_with_port_none_means_the_scheme_default() -> None:
    url = parse_url("https://example.com:8443/").with_port(None)
    assert url.port == 443 == parse_url("https://example.com/").port
    assert str(url) == "https://example.com/"


def test_parser_rules_apply_to_derived_urls() -> None:
    with pytest.raises(UnsupportedSchemeError):
        parse_url_local("file:///etc/hosts", allow_custom_scheme=True).with_port(80)


@pytest.mark.parametrize("path", ["evil.com/x", "c/d", "x"])
def test_a_relative_path_cannot_merge_into_the_authority(path: str) -> None:
    """with_path("evil.com/x") used to serialize as https://example.comevil.com/x -- another host."""
    url = parse_url("https://example.com/").with_path(path)
    assert url.path == f"/{path}"
    assert parse_url(str(url)).host == "example.com"


def test_build_adds_the_leading_slash_its_docstring_promises() -> None:
    assert build("https", "example.com", path="api") == "https://example.com/api"


def test_query_string_wins_when_both_views_are_given() -> None:
    url = parse_url("https://example.com/").copy(query="a=1", query_pairs=[("b", "2")])
    assert url.query == "a=1"
    assert url.query_params == [("a", "1")]
