"""
Comprehensive RFC 3986 compliance tests for URL parsing and building.

This test suite covers the examples and edge cases specified in RFC 3986
to ensure full compliance with the URI specification.
"""
import pytest
from urlps import parse_url, parse_url_unsafe, compose_url
from urlps._parser import Parser
from urlps._builder import Builder
from urlps.exceptions import InvalidURLError


class TestRFC3986Examples:
    """Test cases from RFC 3986 Section 1.1.2 and Appendix B."""

    def test_ftp_example(self):
        """RFC 3986 example: ftp://ftp.is.co.za/rfc/rfc1808.txt"""
        url = parse_url("ftp://ftp.is.co.za/rfc/rfc1808.txt")
        assert url.scheme == "ftp"
        assert url.host == "ftp.is.co.za"
        assert url.path == "/rfc/rfc1808.txt"
        assert url.port == 21  # default FTP port

    def test_http_example_with_fragment(self):
        """RFC 3986 example: http://www.ietf.org/rfc/rfc2396.txt"""
        url = parse_url("http://www.ietf.org/rfc/rfc2396.txt#section5")
        assert url.scheme == "http"
        assert url.host == "www.ietf.org"
        assert url.path == "/rfc/rfc2396.txt"
        assert url.fragment == "section5"

    def test_ldap_example(self):
        """RFC 3986 example with query"""
        # Use parse_url_unsafe for RFC compliance tests with non-public IPs
        url = parse_url_unsafe("ldap://[2001:db8::7]/c=GB?objectClass?one", allow_custom_scheme=True)
        assert url.scheme == "ldap"
        assert url.host == "[2001:db8::7]"
        assert url.path == "/c=GB"
        assert url.query == "objectClass?one"

    def test_mailto_example(self):
        """RFC 3986 example: mailto:John.Doe@example.com"""
        # Note: mailto doesn't have authority, but we can parse it as custom scheme
        parser = Parser()
        parser.custom_scheme = True
        result = parser.parse("mailto:John.Doe@example.com")
        assert result["scheme"] == "mailto"

    def test_telnet_example(self):
        """RFC 3986 example: telnet://192.0.2.16:80/"""
        # Use parse_url_unsafe for RFC compliance tests with documentation IPs
        url = parse_url_unsafe("telnet://192.0.2.16:80/")
        assert url.scheme == "telnet"
        assert url.host == "192.0.2.16"
        assert url.port == 80
        assert url.path == "/"


class TestReservedCharacters:
    """Test handling of reserved and unreserved characters per RFC 3986 Section 2."""

    def test_unreserved_characters_in_path(self):
        """Unreserved characters: ALPHA / DIGIT / '-' / '.' / '_' / '~'"""
        url = parse_url("http://example.com/path-with_dots.and~tildes123")
        assert url.path == "/path-with_dots.and~tildes123"

    def test_reserved_gen_delims_in_query(self):
        """gen-delims: ':' / '/' / '?' / '#' / '[' / ']' / '@'"""
        url = parse_url("http://example.com/?key=value:with/chars")
        assert "key=value:with/chars" in url.query

    def test_reserved_sub_delims_in_query(self):
        """sub-delims: '!' / '$' / '&' / "'" / '(' / ')' / '*' / '+' / ',' / ';' / '='"""
        url = parse_url("http://example.com/?key=val$with!chars()*+,;")
        assert url.query is not None

    def test_percent_encoding_in_path(self):
        """Test percent-encoded octets in path"""
        url = parse_url("http://example.com/path%20with%20spaces")
        assert url.path == "/path%20with%20spaces"

    def test_percent_encoding_normalization(self):
        """Percent-encoding should be normalized to uppercase"""
        components = {
            "scheme": "http",
            "host": "example.com",
            "path": "/test path"
        }
        result = compose_url(components)
        assert "%20" in result  # Uppercase hex digits
        assert "%2f" not in result.lower() or "%2F" in result


class TestPathNormalization:
    """Test path normalization per RFC 3986 Section 6.2.2."""

    def test_dot_segments_removal(self):
        """Test removal of . and .. segments"""
        # Use parse_url_unsafe for RFC compliance tests with path traversal patterns
        cases = [
            ("http://example.com/a/b/c/./../../g", "/a/g"),
            ("http://example.com/./foo", "/foo"),
            ("http://example.com/foo/.", "/foo/"),
            ("http://example.com/foo/./bar", "/foo/bar"),
            ("http://example.com/../foo", "/foo"),
            ("http://example.com/foo/..", "/"),
            ("http://example.com/foo/../bar", "/bar"),
            ("http://example.com/foo/../../bar", "/bar"),
        ]
        for input_url, expected_path in cases:
            url = parse_url_unsafe(input_url)
            assert url.path == expected_path, f"Failed for {input_url}"

    def test_multiple_consecutive_slashes(self):
        """Multiple slashes should be normalized"""
        # Use parse_url_unsafe for RFC compliance tests with path patterns
        url = parse_url_unsafe("http://example.com//a///b//c")
        assert url.path == "/a/b/c"

    def test_trailing_slash_preservation(self):
        """Trailing slashes should be preserved"""
        url = parse_url("http://example.com/a/b/c/")
        assert url.path == "/a/b/c/"

    def test_root_path(self):
        """Root path should be normalized to /"""
        url = parse_url("http://example.com/")
        assert url.path == "/"

    def test_empty_path_with_authority(self):
        """Empty path with authority should become /"""
        url = parse_url("http://example.com")
        assert url.path == "/"


class TestAuthorityComponent:
    """Test authority component per RFC 3986 Section 3.2."""

    def test_userinfo_with_colon(self):
        """Userinfo can contain colons in password"""
        url = parse_url("http://user:pass:word@example.com/")
        assert url.userinfo == "user:pass:word"

    def test_userinfo_without_password(self):
        """Userinfo without password"""
        url = parse_url("http://user@example.com/")
        assert url.userinfo == "user"

    def test_empty_password(self):
        """Empty password should be allowed"""
        url = parse_url("http://user:@example.com/")
        assert url.userinfo == "user:"

    def test_host_case_insensitive(self):
        """Host names are case-insensitive"""
        url1 = parse_url("http://EXAMPLE.COM/path")
        url2 = parse_url("http://example.com/path")
        # Both should work, though case may be preserved
        assert url1.host.lower() == url2.host.lower()

    def test_ipv4_address(self):
        """IPv4 address as host"""
        # Use parse_url_unsafe for RFC compliance tests with private IPs
        url = parse_url_unsafe("http://192.168.1.1:8080/")
        assert url.host == "192.168.1.1"
        assert url.port == 8080

    def test_ipv6_address_simple(self):
        """IPv6 address as host"""
        # Use parse_url_unsafe for RFC compliance tests with documentation IPs
        url = parse_url_unsafe("http://[2001:db8::1]/")
        assert url.host == "[2001:db8::1]"

    def test_ipv6_address_with_port(self):
        """IPv6 address with port"""
        # Use parse_url_unsafe for RFC compliance tests with documentation IPs
        url = parse_url_unsafe("http://[2001:db8::1]:8080/")
        assert url.host == "[2001:db8::1]"
        assert url.port == 8080

    def test_ipv6_compressed_zeros(self):
        """IPv6 with compressed zeros"""
        # Use parse_url_unsafe for RFC compliance tests with loopback
        url = parse_url_unsafe("http://[::1]/")
        assert url.host == "[::1]"

    def test_port_default_http(self):
        """Default port 80 for HTTP"""
        url = parse_url("http://example.com:80/")
        assert url.port == 80
        assert url.effective_port == 80

    def test_port_default_https(self):
        """Default port 443 for HTTPS"""
        url = parse_url("https://example.com/")
        assert url.port == 443
        assert url.effective_port == 443


class TestQueryComponent:
    """Test query component per RFC 3986 Section 3.4."""

    def test_empty_query(self):
        """Empty query string (?) vs no query"""
        url_with_empty = parse_url("http://example.com/?")
        url_without = parse_url("http://example.com/")
        assert url_with_empty.query == ""
        assert url_without.query is None

    def test_query_with_equals(self):
        """Query with key=value pairs"""
        url = parse_url("http://example.com/?key1=val1&key2=val2")
        assert url.query_params == [("key1", "val1"), ("key2", "val2")]

    def test_query_without_values(self):
        """Query with keys but no values"""
        url = parse_url("http://example.com/?flag1&flag2")
        assert url.query_params == [("flag1", None), ("flag2", None)]

    def test_query_mixed_format(self):
        """Query with mixed key=value and key-only"""
        url = parse_url("http://example.com/?key=value&flag")
        assert url.query_params == [("key", "value"), ("flag", None)]

    def test_query_duplicate_keys(self):
        """Query can have duplicate keys"""
        url = parse_url("http://example.com/?key=val1&key=val2")
        assert url.query_params == [("key", "val1"), ("key", "val2")]

    def test_query_special_chars(self):
        """Query with special characters"""
        url = parse_url("http://example.com/?key=value+with+plus")
        # Plus should be decoded to space
        assert any("value with plus" in str(v) for k, v in url.query_params)


class TestFragmentComponent:
    """Test fragment component per RFC 3986 Section 3.5."""

    def test_fragment_simple(self):
        """Simple fragment identifier"""
        url = parse_url("http://example.com/#section1")
        assert url.fragment == "section1"

    def test_fragment_with_slash(self):
        """Fragment can contain slashes"""
        url = parse_url("http://example.com/#section/subsection")
        assert url.fragment == "section/subsection"

    def test_fragment_with_query_like_chars(self):
        """Fragment can contain query-like characters"""
        url = parse_url("http://example.com/#key=value&foo=bar")
        assert url.fragment == "key=value&foo=bar"

    def test_empty_fragment(self):
        """Empty fragment (#) vs no fragment"""
        url_with = parse_url("http://example.com/#")
        url_without = parse_url("http://example.com/")
        assert url_with.fragment == ""
        assert url_without.fragment is None


class TestSchemeSpecific:
    """Test scheme-specific behaviors per RFC 3986 Section 3.1."""

    def test_scheme_case_insensitive(self):
        """Scheme is case-insensitive"""
        url1 = parse_url("HTTP://example.com/")
        url2 = parse_url("http://example.com/")
        assert url1.scheme.lower() == url2.scheme.lower()

    def test_scheme_normalization(self):
        """Scheme should be normalized to lowercase"""
        url = parse_url("HTTP://example.com/")
        assert url.scheme == "http"

    def test_file_scheme_no_port(self):
        """File scheme should not allow ports"""
        with pytest.raises(InvalidURLError):
            parse_url("file://localhost:8080/path")

    def test_file_scheme_with_host(self):
        """File scheme with localhost"""
        url = parse_url("file:///path/to/file", allow_custom_scheme=True)
        assert url.scheme == "file"
        assert url.path == "/path/to/file"


class TestEdgeCases:
    """Additional edge cases for RFC 3986 compliance."""

    def test_url_with_at_in_userinfo(self):
        """@ symbol in password should be percent-encoded"""
        # This should fail as @ is the delimiter
        with pytest.raises(InvalidURLError):
            parse_url("http://user:p@ss@example.com/")

    def test_extremely_long_url(self):
        """Very long URLs should be handled"""
        long_path = "/a" * 1000
        url = parse_url(f"http://example.com{long_path}")
        assert url.path == "/a" * 1000

    def test_unicode_in_host(self):
        """Unicode in host should be IDNA-encoded"""
        url = parse_url("http://münchen.de/")
        # Should be punycode encoded
        assert "xn--" in url.host

    def test_unicode_in_path(self):
        """Unicode in path should be percent-encoded"""
        result = compose_url({
            "scheme": "http",
            "host": "example.com",
            "path": "/путь"
        })
        assert "%" in result  # Should be percent-encoded

    def test_relative_reference_no_scheme(self):
        """Relative reference without scheme"""
        parser = Parser()
        result = parser.parse("//example.com/path")
        assert result["scheme"] is None
        assert result["host"] == "example.com"
        assert result["path"] == "/path"

    def test_path_only_reference(self):
        """Path-only reference"""
        parser = Parser()
        result = parser.parse("/path/to/resource")
        assert result["scheme"] is None
        assert result["host"] is None
        assert result["path"] == "/path/to/resource"

    def test_query_only_reference(self):
        """Query-only reference"""
        parser = Parser()
        result = parser.parse("?query=string")
        assert result["scheme"] is None
        assert result["query"] == "query=string"

    def test_fragment_only_reference(self):
        """Fragment-only reference"""
        parser = Parser()
        result = parser.parse("#fragment")
        assert result["scheme"] is None
        assert result["fragment"] == "fragment"


class TestCompositionRoundTrip:
    """Test that parsing and composing maintain URL integrity."""

    def test_simple_url_roundtrip(self):
        """Simple URL should round-trip"""
        original = "http://example.com/path?query=value#fragment"
        url = parse_url(original)
        reconstructed = url.as_string()
        # Parse both to normalize
        assert parse_url(reconstructed).as_string() == url.as_string()

    def test_complex_url_roundtrip(self):
        """Complex URL with all components should round-trip"""
        original = "https://user:pass@example.com:8443/path/to/resource?key1=val1&key2=val2#section"
        url = parse_url(original)
        reconstructed = url.as_string()
        url2 = parse_url(reconstructed)
        assert url2.scheme == url.scheme
        assert url2.userinfo == url.userinfo
        assert url2.host == url.host
        assert url2.port == url.port
        assert url2.path == url.path
        assert url2.query_params == url.query_params
        assert url2.fragment == url.fragment

    def test_ipv6_url_roundtrip(self):
        """IPv6 URL should round-trip"""
        # Use parse_url_unsafe for RFC compliance tests with documentation IPs
        original = "http://[2001:db8::1]:8080/path"
        url = parse_url_unsafe(original)
        reconstructed = url.as_string()
        url2 = parse_url_unsafe(reconstructed)
        assert url2.host == "[2001:db8::1]"
        assert url2.port == 8080


class TestPercentEncodingNormalization:
    """Test percent-encoding normalization per RFC 3986 Section 6.2.2.2."""

    def test_uppercase_percent_encoding(self):
        """Percent-encoding should use uppercase hex digits"""
        builder = Builder()
        encoded = builder.percent_encode("hello world", safe="")
        # All percent encodings should be uppercase
        assert "%20" in encoded or "%2D" in encoded  # Space or other encoded chars
        assert all(c.isupper() for c in encoded if c.isalpha() and encoded[encoded.index(c)-1] == '%')

    def test_unreserved_chars_not_encoded(self):
        """Unreserved characters should not be percent-encoded"""
        builder = Builder()
        unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        encoded = builder.percent_encode(unreserved, safe=builder.PATH_SAFE)
        # Should not introduce any new percent-encoding for unreserved chars
        assert "%" not in encoded or encoded.count("%") == unreserved.count("%")


class TestCaseNormalization:
    """Test case normalization per RFC 3986 Section 6.2.2.1."""

    def test_scheme_lowercase(self):
        """Scheme should be normalized to lowercase"""
        url = parse_url("HTTP://example.com/")
        assert url.scheme == "http"

    def test_host_lowercase_recommended(self):
        """Host should typically be lowercase (though case-insensitive)"""
        url = parse_url("http://EXAMPLE.COM/")
        # The implementation may preserve case, but comparison should be case-insensitive
        assert url.host.lower() == "example.com"


class TestPathSegmentNormalization:
    """Additional path segment normalization tests."""

    def test_double_dot_at_root(self):
        """.. at root should not go above root"""
        # Use parse_url_unsafe for RFC compliance tests with path traversal patterns
        url = parse_url_unsafe("http://example.com/../foo")
        assert url.path == "/foo"

    def test_multiple_double_dots(self):
        """Multiple .. segments"""
        # Use parse_url_unsafe for RFC compliance tests with path traversal patterns
        url = parse_url_unsafe("http://example.com/a/b/c/../../d")
        assert url.path == "/a/d"

    def test_dot_segments_with_trailing_slash(self):
        """Dot segments with trailing slash"""
        # Use parse_url_unsafe for RFC compliance tests with path traversal patterns
        url = parse_url_unsafe("http://example.com/a/b/./c/../")
        assert url.path == "/a/b/"

    def test_only_dots(self):
        """Path with only dots"""
        # Use parse_url_unsafe for RFC compliance tests with path traversal patterns
        url = parse_url_unsafe("http://example.com/./././")
        assert url.path == "/"
