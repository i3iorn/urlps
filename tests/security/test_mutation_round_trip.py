"""Derived URLs (copy()/with_*()) must mean exactly what their string means.

copy() assembles a URL from components rather than parsing one, and used to
apply weaker rules than parse_url(): with_scheme() bypassed the scheme
allowlist and kept the old default port, userinfo was emitted unescaped (so
"169.254.169.254#" moved the host for every other parser), a "#" in a query
override became a fragment, and escaped fragments were double-encoded on
every serialization.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from urlps import InvalidURLError, URLBuildError, build, parse_url, parse_url_local
from urlps._mutations import _URLMutations

# ---------------------------------------------------------------------------
# with_scheme()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "start,scheme,expected_port,expected_str",
    [
        ("https://example.com/x", "http", 80, "http://example.com/x"),
        ("http://example.com/x", "https", 443, "https://example.com/x"),
        ("https://example.com/x", "wss", 443, "wss://example.com/x"),
        ("https://example.com:8443/x", "http", 8443, "http://example.com:8443/x"),  # explicit port is kept
        ("https://example.com/x", "HTTP", 80, "http://example.com/x"),
    ],
)
def test_with_scheme_resets_only_a_default_port(start: str, scheme: str, expected_port: int, expected_str: str) -> None:
    url = parse_url(start).with_scheme(scheme)
    assert url.port == expected_port
    assert str(url) == expected_str
    assert url.scheme == scheme.lower()
    assert url.recognized_scheme is True


def test_explicit_port_override_wins_over_the_reset() -> None:
    url = parse_url("https://example.com/").copy(scheme="http", port=8080)
    assert (url.scheme, url.port, str(url)) == ("http", 8080, "http://example.com:8080/")


# ---------------------------------------------------------------------------
# userinfo
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "userinfo,encoded",
    [
        ("admin:p#ss/w?rd", "admin:p%23ss%2Fw%3Frd"),
        ("user:pa ss", "user:pa%20ss"),
        ("x\\y", "x%5Cy"),
        ("üser:pw", "%C3%BCser:pw"),
        ("user:p%41ss", "user:pAss"),  # valid escape kept (and §6.2.2-normalized), not re-encoded
        ("user:100%", "user:100%25"),  # a stray "%" is encoded
        ("u!$&'()*+,;=:x", "u!$&'()*+,;=:x"),  # sub-delims are legal userinfo
    ],
)
def test_userinfo_is_stored_and_serialized_in_rfc_3986_form(userinfo: str, encoded: str) -> None:
    url = parse_url("https://example.com/", policy="internal").with_userinfo(userinfo)
    assert url.userinfo == encoded
    assert str(url) == f"https://{encoded}@example.com/"
    assert urlsplit(str(url)).hostname == "example.com"
    assert parse_url(str(url), policy="internal").userinfo == encoded


def test_parsed_userinfo_is_normalized_the_same_way() -> None:
    url = parse_url_local("http://a\\b@example.com/")
    assert url.userinfo == "a%5Cb"
    assert str(url) == "http://a%5Cb@example.com/"
    assert parse_url_local("http://üser:pw@example.com/").userinfo == "%C3%BCser:pw"


def test_build_escapes_userinfo_too() -> None:
    assert build("http", "example.com", userinfo="a@b:p#") == "http://a%40b:p%23@example.com/"


def test_lone_surrogate_userinfo_is_rejected_cleanly() -> None:
    with pytest.raises(InvalidURLError):
        parse_url("https://example.com/", policy="internal").with_userinfo("x\ud800")
    with pytest.raises(URLBuildError):
        build("http", "example.com", userinfo="x\ud800")
    with pytest.raises(URLBuildError):
        build("http", "example.com", fragment="x\ud800")


# ---------------------------------------------------------------------------
# query and fragment
# ---------------------------------------------------------------------------


def test_hash_in_a_query_override_is_rejected() -> None:
    with pytest.raises(InvalidURLError, match="%23"):
        parse_url("https://example.com/").with_query("a=1#frag")
    assert parse_url("https://example.com/").with_query("a=1%23frag").query == "a=1%23frag"


def test_query_override_is_normalized_like_a_parsed_query() -> None:
    url = parse_url("https://example.com/").with_query("a=%7e&b=%2f")
    assert url.query == "a=~&b=%2F"
    assert parse_url(str(url)).query == url.query


@pytest.mark.parametrize("fragment", ["a%2Fb", "100%25", "sec[1]", "x y".replace(" ", "%20"), "%41"])
def test_fragment_serialization_is_stable(fragment: str) -> None:
    """Every round trip used to add another layer of encoding: %2F -> %252F -> %25252F."""
    url = parse_url(f"https://example.com/#{fragment}")
    first = str(url)
    assert str(parse_url(first)) == first
    assert str(parse_url(str(parse_url(first)))) == first
    assert "%25" not in first or "%25" in fragment


def test_with_fragment_normalizes_escapes() -> None:
    url = parse_url("https://example.com/").with_fragment("%41b")
    assert url.fragment == "Ab"
    assert str(url) == "https://example.com/#Ab"


# ---------------------------------------------------------------------------
# The round-trip assertion itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "component,value",
    [("_query", "a#b"), ("_host", "other.example"), ("_userinfo", "a@b"), ("_port", 0), ("_scheme", "HTTPS")],
)
def test_round_trip_assertion_detects_a_disagreeing_component(component: str, value: object) -> None:
    url = parse_url("https://user@example.com/x?q=1#f")
    object.__setattr__(url, "_frozen", False)
    object.__setattr__(url, component, value)
    if component == "_host":
        # A host disagreement cannot arise from serialization; simulate the
        # parser seeing something else by changing the builder's view.
        object.__setattr__(url, "_userinfo", "x@other.example")
    with pytest.raises(InvalidURLError, match=r"round-trip|re-parse"):
        _URLMutations._assert_round_trip(url)


def test_round_trip_assertion_accepts_every_ordinary_derivation() -> None:
    base = parse_url("https://user:pw@example.com:8443/a/b?q=1#frag")
    for derived in (
        base.with_host("other.example"),
        base.with_port(None),
        base.with_path("/c/../d"),
        base.with_query("x=%7e"),
        base.with_query(None),
        base.with_fragment(""),
        base.with_userinfo(None),
        base.with_query_param("k", "v & w"),
        base.without_query_param("q"),
        base.canonicalize(),
    ):
        assert parse_url(str(derived)).host == derived.host


def test_long_non_ascii_components_still_derive() -> None:
    """Percent-encoding makes these longer than the parse limits; derivation must not fail on that."""
    user, path, fragment = "\u00fc" * 100, "\U0001f600" * 2000, "[" * 900
    url = parse_url_local(f"http://{user}:pw@example.com/{path}#{fragment}")
    derived = url.with_query("a=1").canonicalize()
    assert derived.host == "example.com"
    assert parse_url_local(str(url)).userinfo == url.userinfo
    assert parse_url_local(str(url)).path == url.as_string().split("example.com", 1)[1].split("#", 1)[0]
