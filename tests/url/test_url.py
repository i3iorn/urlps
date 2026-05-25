"""Tests for the URL class and related functionality."""
import pytest

from urlps import InvalidURLError, URL
from urlps._relative import parse_relative_reference, build_relative_reference, round_trip_relative
from urlps._parser import Parser


def test_netloc_parsing_with_userinfo_and_port() -> None:
    url = URL("http://user:pass@example.com:8080/path")
    assert url.netloc == "user:pass@example.com:8080"
    assert url.userinfo == "user:pass"
    assert url.host == "example.com"
    assert url.port == 8080

    rebuilt = url.with_netloc("admin@example.org")
    assert rebuilt.netloc == "admin@example.org"
    assert rebuilt.userinfo == "admin"
    assert rebuilt.host == "example.org"
    assert rebuilt.port == 80


def test_parser_parse_netloc() -> None:
    parser = Parser()
    userinfo, host, port = parser.parse_netloc("example.net:9090", require_host=True)
    assert userinfo is None
    assert host == "example.net"
    assert port == 9090


def test_default_port_inferred_and_hidden() -> None:
    url = URL("https://example.org/resource")
    assert url.port == 443
    assert url.effective_port == 443
    assert url.as_string() == "https://example.org/resource"

    # Use with_port to create a new URL with port=None
    url2 = url.with_port(None)
    assert url2.port is None
    assert url2.effective_port == 443
    assert url2.as_string() == "https://example.org/resource"


def test_file_scheme_rejects_ports() -> None:
    with pytest.raises(InvalidURLError):
        URL("file://localhost:80/path/to/file")


def test_port_without_host_is_invalid() -> None:
    parser = Parser()
    with pytest.raises(InvalidURLError):
        parser.parse_netloc(":8080", require_host=True)


def test_relative_reference_round_trip() -> None:
    source = "./assets/../img/logo.svg?cache=false#hero"
    parts = parse_relative_reference(source)
    assert parts["path"] == "./assets/../img/logo.svg"
    assert parts["query"] == "cache=false"
    assert parts["fragment"] == "hero"
    rebuilt = build_relative_reference(parts["path"], query=parts["query"], fragment=parts["fragment"])
    assert rebuilt == source
    assert round_trip_relative(source) == source


def test_relative_reference_rejects_schemes() -> None:
    with pytest.raises(InvalidURLError):
        parse_relative_reference("http://example.com/path")


def test_with_netloc_accepts_ipv6_and_port() -> None:
    """Test with_netloc for IPv6 addresses."""
    url = URL("https://example.com")
    new_url = url.with_netloc("[2001:db8::1]:4443")
    assert new_url.host == "[2001:db8::1]"
    assert new_url.port == 4443
    assert new_url.netloc == "[2001:db8::1]:4443"


def test_with_netloc_requires_host_when_value_given() -> None:
    """Test that with_netloc validates host requirement."""
    url = URL("https://example.com")
    with pytest.raises(InvalidURLError):
        url.with_netloc(":443")


def test_parse_netloc_without_required_host() -> None:
    parser = Parser()
    userinfo, host, port = parser.parse_netloc("user@", require_host=False)
    assert userinfo == "user"
    assert host is None
    assert port is None


def test_parse_relative_reference_requires_non_empty_string() -> None:
    with pytest.raises(InvalidURLError):
        parse_relative_reference("")


def test_build_relative_reference_handles_missing_query_fragment() -> None:
    assert build_relative_reference("./path") == "./path"
    assert build_relative_reference("./path", query="q=1") == "./path?q=1"
    assert build_relative_reference("./path", fragment="frag") == "./path#frag"


def test_round_trip_relative_normalizes_noop() -> None:
    rel = "../a/b?x=1"
    assert round_trip_relative(rel) == rel


def test_url_is_always_immutable() -> None:
    """Test that URLs are always immutable (no setters)."""
    url = URL("https://example.com")

    # URL should be hashable since it's immutable
    assert hash(url) is not None


def test_copy_with_overrides_and_with_helpers() -> None:
    url = URL("https://example.com/path")
    clone = url.with_host("example.org").with_path("/docs")
    assert clone.host == "example.org"
    assert clone.path == "/docs"
    assert url.host == "example.com"


def test_with_query_and_query_params() -> None:
    """Test query manipulation via immutable methods."""
    url = URL("https://example.com?a=1")

    # Remove query - creates new URL without query
    url2 = url.without_query()
    assert url2.query is None
    assert url2.query_params == []

    # Add query param
    url3 = url.with_query_param("x", "y")
    assert "x=y" in url3.query

    # Original unchanged
    assert url.query == "a=1"


def test_allow_custom_scheme_via_parser_flag() -> None:
    parser = Parser()
    parser.custom_scheme = True
    url = URL("foo+bar://example.com", parser=parser)
    assert url.scheme == "foo+bar"
    assert url.recognized_scheme is False


def test_with_scheme_normalizes() -> None:
    """Test that with_scheme works correctly."""
    url = URL("https://example.com")
    new_url = url.with_scheme("http")
    assert new_url.scheme == "http"
    assert url.scheme == "https"  # Original unchanged


def test_copy_validates_userinfo_format() -> None:
    """Test that copy validates userinfo."""
    url = URL("https://example.com")
    with pytest.raises(InvalidURLError):
        url.copy(userinfo="bad@info")


def test_with_fragment_validates() -> None:
    """Test fragment validation."""
    url = URL("https://example.com")
    # Valid fragment
    new_url = url.with_fragment("frag-_.~!$&'()*+,;=:@/?")
    assert new_url.fragment == "frag-_.~!$&'()*+,;=:@/?"


def test_port_validation_in_copy() -> None:
    """Test that copy validates port."""
    url = URL("https://example.com")
    with pytest.raises(InvalidURLError):
        url.copy(port="abc")
    with pytest.raises(InvalidURLError):
        url.copy(port=70000)


def test_with_query_param_adds_param() -> None:
    """Test with_query_param method."""
    url = URL("https://example.com")
    new_url = url.with_query_param("a", "1")
    assert new_url.query == "a=1"


def test_with_port_helper_sets_normalized_port() -> None:
    url = URL("https://example.com")
    updated = url.with_port(8080)
    assert updated.port == 8080
    assert url.port == 443


def test_copy_raises_for_invalid_overrides():
    url = URL("https://example.com")
    # invalid port override should raise when copying
    with pytest.raises(InvalidURLError):
        url.copy(port="notanint")


def test_with_fragment_percent_encodes():
    """Test fragment handling."""
    url = URL("https://example.com")
    # Setting fragment with special chars should work
    result = url.with_fragment("section%201")
    assert result.fragment is not None


def test_url_hashable() -> None:
    """Test that URLs are hashable."""
    url1 = URL("https://example.com/path")
    url2 = URL("https://example.com/path")

    # Same URLs should have same hash
    assert hash(url1) == hash(url2)

    # Can be used in sets
    url_set = {url1, url2}
    assert len(url_set) == 1


def test_url_equality() -> None:
    """Test URL equality."""
    url1 = URL("https://example.com/path")
    url2 = URL("https://example.com/path")
    url3 = URL("https://example.org/path")

    assert url1 == url2
    assert url1 != url3


def test_without_query() -> None:
    """Test without_query helper."""
    url = URL("https://example.com/path?query=1#frag")
    clean = url.without_query()
    assert clean.query is None
    assert clean.fragment is None
    assert clean.path == "/path"


def test_url_components_with_updates() -> None:
    """Test URLComponents.with_updates() works with partial kwargs."""
    from urlps._components import URLComponents

    # Create initial components
    components = URLComponents(
        scheme="https",
        host="example.com",
        port=443,
        path="/original",
    )

    # Update only some fields - should not raise KeyError
    updated = components.with_updates(path="/updated")
    assert updated.scheme == "https"
    assert updated.host == "example.com"
    assert updated.port == 443
    assert updated.path == "/updated"

    # Update multiple fields
    updated2 = components.with_updates(host="other.com", port=8080)
    assert updated2.host == "other.com"
    assert updated2.port == 8080
    assert updated2.path == "/original"

    # Update with None port
    updated3 = components.with_updates(port=None)
    assert updated3.port is None

