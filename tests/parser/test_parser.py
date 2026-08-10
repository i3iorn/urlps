import pytest

from urlps._parser import Parser
from urlps.exceptions import InvalidURLError


def test_parse_sets_recognized_scheme_flag() -> None:
    parser = Parser()
    parser.parse("https://example.com")
    assert parser.recognized_scheme is True


def test_parse_rejects_invalid_scheme() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("1http://example.com")


def test_custom_scheme_allowed_when_flag_set() -> None:
    parser = Parser()
    parser.custom_scheme = True
    parsed = parser.parse("foo+bar://example.com")
    assert parsed["scheme"] == "foo+bar"
    assert parser.recognized_scheme is False


def test_parse_host_requires_authority_for_absolute_urls() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("https:///path")


def test_parse_ipv6_literal_requires_closing_bracket() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("http://[2001:db8::1/path")


def test_parse_userinfo_validation() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("http://user@:example.com")


def test_parse_path_normalization_and_trailing_slash() -> None:
    parser = Parser()
    parsed = parser.parse("http://example.com/a/./b/../c/")
    assert parsed["path"] == "/a/c/"


def test_parse_query_preserves_order_and_duplicates() -> None:
    parser = Parser()
    parsed = parser.parse("http://example.com/?a=1&a=2&flag")
    assert parser.query_pairs == [("a", "1"), ("a", "2"), ("flag", None)]
    assert parsed["query"] == "a=1&a=2&flag"


def test_parse_fragment_validation() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("http://example.com/#invalid space")


def test_parse_netloc_respects_require_host_flag() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse_netloc(":443", require_host=True)
    userinfo, host, port = parser.parse_netloc("user@example.com:8080", require_host=False)
    assert userinfo == "user"
    assert host == "example.com"
    assert port == 8080


def test_parse_applies_default_ports_and_validates_file_scheme() -> None:
    parser = Parser()
    parsed = parser.parse("https://example.com")
    assert parsed["port"] == 443
    with pytest.raises(InvalidURLError):
        parser.parse("file://localhost:99/path")


def test_fragment_regex_edge_cases() -> None:
    parser = Parser()
    parsed = parser.parse("http://example.com/#frag!$&'()*+,;=:@/?")
    assert parsed["fragment"] == "frag!$&'()*+,;=:@/?"
    with pytest.raises(InvalidURLError):
        parser.parse("http://example.com/#bad%fragment")


def test_parse_rejects_non_string_or_blank_input() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("   ")
    with pytest.raises(InvalidURLError):
        parser.parse(123)  # type: ignore[arg-type]


def test_parse_relative_url_without_scheme() -> None:
    parser = Parser()
    parsed = parser.parse("docs/guide?foo=bar")
    assert parsed["scheme"] is None
    assert parsed["host"] is None
    assert parsed["path"] == "docs/guide"
    assert parsed["query"] == "foo=bar"


def test_parse_requires_authority_when_scheme_missing_host_only_slashes() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("http://")


def test_parse_userinfo_requires_username() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("http://:pass@example.com")


def test_parse_accepts_ipv6_literal_with_port() -> None:
    parser = Parser()
    parsed = parser.parse("http://[2001:db8::1]:8080/foo")
    assert parsed["host"] == "[2001:db8::1]"
    assert parsed["port"] == 8080


def test_parse_ipv6_literal_rejects_trailing_garbage() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("http://[2001:db8::1]oops")


def test_parse_host_rejects_invalid_characters() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("http://exa$mple.com")


def test_parse_host_idna_encoding_failure() -> None:
    parser = Parser()
    bad_label = "\udcff"
    with pytest.raises(InvalidURLError):
        parser.parse(f"http://{bad_label}.com")


def test_parse_port_must_be_numeric() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("http://example.com:abc")


def test_parse_port_range_check() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("http://example.com:70000")


def test_parse_handles_empty_query_string() -> None:
    parser = Parser()
    parsed = parser.parse("http://example.com/?")
    assert parsed["query"] == ""
    assert parser.query_pairs == []


def test_parse_query_skips_empty_chunks() -> None:
    """Empty chunks are ignored when building pairs, but the raw query is kept.

    Parsing is non-destructive: the query string round-trips byte-for-byte
    even when it contains a semantically empty chunk. Only the decoded pairs
    skip it.
    """
    parser = Parser()
    parsed = parser.parse("http://example.com/?a=1&&b=2")
    assert parsed["query"] == "a=1&&b=2"
    assert parser.query_pairs == [("a", "1"), ("b", "2")]


def test_parse_query_rejects_empty_keys() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("http://example.com/?=value")

def test_single_character_scheme() -> None:
    parser = Parser()
    parsed = parser.parse("a://example.com")
    assert parsed["scheme"] == "a"
    assert parser.recognized_scheme is False

def test_parse_path_with_multiple_consecutive_slashes() -> None:
    parser = Parser()
    parsed = parser.parse("http://example.com//a///b/c")
    assert parsed["path"] == "/a/b/c"

def test_parse_path_with_only_dots() -> None:
    parser = Parser()
    parsed = parser.parse("http://example.com/././.")
    assert parsed["path"] == "/"


def test_parse_relative_url_with_scheme_separator_in_query() -> None:
    """A relative reference must not be mistaken for absolute just because
    '://' appears later, e.g. in a redirect-target query value."""
    parser = Parser()
    parsed = parser.parse("/redirect?url=http://evil.com")
    assert parsed["scheme"] is None
    assert parsed["host"] is None
    assert parsed["path"] == "/redirect"
    assert parsed["query"] == "url=http://evil.com"


def test_parse_relative_url_with_scheme_separator_in_query_no_leading_slash() -> None:
    parser = Parser()
    parsed = parser.parse("relative/path?x=ftp://y")
    assert parsed["scheme"] is None
    assert parsed["host"] is None
    assert parsed["path"] == "relative/path"
    assert parsed["query"] == "x=ftp://y"


def test_parse_still_detects_real_scheme_before_embedded_separator() -> None:
    """The first '://' is the real separator even when a second one appears
    later in the query string."""
    parser = Parser()
    parsed = parser.parse("http://example.com/a?b=ftp://c")
    assert parsed["scheme"] == "http"
    assert parsed["host"] == "example.com"
    assert parsed["query"] == "b=ftp://c"


def test_parse_still_rejects_genuinely_invalid_absolute_scheme() -> None:
    """Scheme validation must still be strict when '://' is the real,
    leading separator (nothing precedes it)."""
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse("1http://example.com")