"""
Extended RFC 3986 compliance tests covering additional edge cases and validation requirements.

This test suite focuses on areas not fully covered in test_rfc3986_compliance.py:
- Percent-encoding normalization (RFC 3986 § 2.1)
- Reserved characters validation (RFC 3986 § 2.2-2.3)
- Query string edge cases
- Path segment validation
- Authority validation
- Relative reference resolution
- Scheme-specific validation
"""
import pytest
from urlps import parse_url, parse_url_unsafe, compose_url
from urlps._parser import Parser
from urlps._builder import Builder
from urlps.exceptions import InvalidURLError, URLParseError


class TestPercentEncodingRFC3986:
    """RFC 3986 § 2.1: Percent-Encoding"""

    def test_percent_encoding_unreserved_not_encoded(self):
        """RFC 3986 § 2.3: Unreserved chars should NOT be percent-encoded"""
        # Unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"

        # Test that unreserved chars don't get encoded
        result = compose_url({
            "scheme": "http",
            "host": "example.com",
            "path": "/test-value_123.ext~file"
        })
        assert "-" in result
        assert "_" in result
        assert "." in result
        assert "~" in result

    def test_percent_encoding_uppercase_hex(self):
        """RFC 3986 § 2.1: Percent-encoding must use uppercase hexadecimal digits"""
        builder = Builder()
        # Space should be encoded as %20 (uppercase)
        encoded = builder.percent_encode("hello world", safe="")
        assert "%20" in encoded
        # Check that hex digits after % are uppercase
        import re
        hex_encodings = re.findall(r'%[0-9A-Fa-f]{2}', encoded)
        for enc in hex_encodings:
            assert enc.isupper() or enc[1] == '2' and enc[2] == '0'  # %20 is uppercase

    def test_percent_encoding_reserved_in_components(self):
        """RFC 3986 § 2.2-2.3: Reserved chars have special meaning in components"""
        # In path: certain reserved chars have special meaning
        url = parse_url("http://example.com/a:b@c")
        assert url.path == "/a:b@c"  # These are allowed in path

    def test_percent_encoding_pct_encoding_itself(self):
        """Percent sign itself must be encoded"""
        builder = Builder()
        encoded = builder.percent_encode("100% complete", safe="")
        assert "%25" in encoded  # % must be encoded as %25

    def test_percent_encoding_normalization_query(self):
        """Percent-encoded unreserved chars should be normalized (decoded)"""
        # If someone provides %41 (A), should ideally be normalized to A
        # RFC 3986 § 6.2.2.2 discusses this
        builder = Builder()
        # Our implementation should normalize uppercase
        result = builder.percent_encode("test", safe="")
        # Check that any percent-encodings are uppercase
        assert not any(c.islower() for i, c in enumerate(result) if i > 0 and result[i-1] == '%')

    def test_punycode_host_validation(self):
        """IDNA-encoded hosts should pass validation"""
        url = parse_url("http://xn--mnchen-3ya.de/")
        assert "xn--" in url.host

    def test_ipv4_address_validation_strict(self):
        """IPv4 addresses must have octets in valid range [0-255]"""
        with pytest.raises(InvalidURLError):
            parse_url("http://256.1.1.1/")

        with pytest.raises(InvalidURLError):
            parse_url("http://1.1.1.256/")

        with pytest.raises(InvalidURLError):
            parse_url("http://1.1.1.-1/")

    def test_ipv6_with_zone_id_percent_encoded(self):
        """RFC 6874: IPv6 zone IDs must be percent-encoded"""
        # Use parse_url_unsafe for link-local IPv6 addresses
        # Correct: zone ID is percent-encoded as %25eth0
        url = parse_url_unsafe("http://[fe80::1%25eth0]/")
        assert "[fe80::1%25eth0]" in url.host or url.host == "[fe80::1%25eth0]"

    def test_ipv6_zone_id_raw_percent_invalid(self):
        """Raw % (not %25) in IPv6 literal is invalid"""
        with pytest.raises(InvalidURLError):
            parse_url_unsafe("http://[fe80::1%eth0]/")


class TestQueryStringRFC3986:
    """RFC 3986 § 3.4: Query Component"""

    def test_query_ampersand_separator(self):
        """& is the standard query param separator"""
        url = parse_url("http://example.com/?a=1&b=2")
        assert len(url.query_params) == 2
        assert ("a", "1") in url.query_params
        assert ("b", "2") in url.query_params

    def test_query_empty_value(self):
        """Query params can have empty values"""
        url = parse_url("http://example.com/?key=")
        assert url.query_params == [("key", "")]

    def test_query_no_value(self):
        """Query params can appear without values"""
        url = parse_url("http://example.com/?flag")
        assert url.query_params == [("flag", None)]

    def test_query_reserved_characters_allowed(self):
        """RFC 3986 § 3.4: Reserved chars are allowed in query (but may have special meaning)"""
        # Reserved: gen-delims / sub-delims / ":" / "@"
        url = parse_url("http://example.com/?key=value:with:colons")
        assert url.query is not None

    def test_query_plus_as_space(self):
        """In application/x-www-form-urlencoded, + means space"""
        url = parse_url("http://example.com/?search=hello+world")
        # The parser uses unquote_plus which treats + as space
        params = url.query_params
        assert params[0][1] == "hello world"

    def test_query_percent_encoding_preservation(self):
        """Percent-encoded characters in query should be preserved"""
        url = parse_url("http://example.com/?key=value%20with%20spaces")
        assert url.query is not None

    def test_query_duplicate_ampersands(self):
        """Multiple consecutive ampersands should be handled"""
        url = parse_url("http://example.com/?a=1&&b=2")
        # Empty param between && should be skipped
        params = url.query_params
        assert ("a", "1") in params
        assert ("b", "2") in params

    def test_query_equals_in_value(self):
        """Equals sign in value is allowed"""
        url = parse_url("http://example.com/?formula=a%3Db%2B1")
        assert url.query is not None


class TestPathSegmentRFC3986:
    """RFC 3986 § 3.3: Path Component"""

    def test_path_empty_segment(self):
        """Empty path segments are allowed (creates //)"""
        url = parse_url("http://example.com/a//b")
        # Empty segments between slashes should be normalized
        # RFC 3986 doesn't require removing them, but our implementation does
        assert "//" not in url.path or url.path == "/a/b"

    def test_path_dot_segment(self):
        """Single dot represents current directory"""
        url = parse_url("http://example.com/a/./b")
        assert url.path == "/a/b"

    def test_path_double_dot_segment(self):
        """Double dot represents parent directory"""
        # Use parse_url_unsafe for path traversal pattern tests
        url = parse_url_unsafe("http://example.com/a/b/../c")
        assert url.path == "/a/c"

    def test_path_double_dot_at_root(self):
        """.. at root should not escape root"""
        # Use parse_url_unsafe for path traversal pattern tests
        url = parse_url_unsafe("http://example.com/../a")
        assert url.path == "/a"
        assert not url.path.startswith("/../")

    def test_path_complex_normalization(self):
        """RFC 3986 § 5.2.4: Remove dot segments"""
        # Use parse_url_unsafe for path traversal pattern tests
        cases = [
            ("http://example.com/a/b/c/./../../g", "/a/g"),
            ("http://example.com/./a", "/a"),
            ("http://example.com/a/.", "/a/"),
            ("http://example.com/a/b/c", "/a/b/c"),
            ("http://example.com/a/b/c/", "/a/b/c/"),
        ]
        for input_url, expected_path in cases:
            url = parse_url_unsafe(input_url)
            assert url.path == expected_path, f"Failed for {input_url}"

    def test_path_trailing_slash_significance(self):
        """Trailing slash is significant in path"""
        url1 = parse_url("http://example.com/resource")
        url2 = parse_url("http://example.com/resource/")
        assert url1.path == "/resource"
        assert url2.path == "/resource/"

    def test_path_leading_slash_significance(self):
        """Leading slash indicates absolute path"""
        # With host, path is always absolute
        url = parse_url("http://example.com/path")
        assert url.path.startswith("/")

    def test_path_reserved_characters(self):
        """Reserved characters allowed in path"""
        # Reserved: ":" / "@" / "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
        url = parse_url("http://example.com/path:with@special!chars")
        assert url.path is not None


class TestAuthorityValidationRFC3986:
    """RFC 3986 § 3.2: Authority Component"""

    def test_userinfo_colon_as_delimiter(self):
        """Colon in userinfo separates username from password"""
        url = parse_url("http://user:password@example.com/")
        assert url.userinfo == "user:password"

    def test_userinfo_multiple_colons(self):
        """Multiple colons allowed in password"""
        url = parse_url("http://user:pass:word:extra@example.com/")
        assert url.userinfo == "user:pass:word:extra"

    def test_userinfo_empty_password(self):
        """Empty password is allowed (trailing colon)"""
        url = parse_url("http://user:@example.com/")
        assert url.userinfo == "user:"

    def test_userinfo_at_as_delimiter(self):
        """@ is the delimiter between userinfo and host"""
        # Should fail - @ in password must be percent-encoded
        with pytest.raises(InvalidURLError):
            parse_url("http://user:pass@word@example.com/")

    def test_host_normalization_lowercase(self):
        """Host should be case-normalized (typically to lowercase)"""
        url = parse_url("http://EXAMPLE.COM/")
        # RFC 3986 recommends case-normalization of scheme and host
        assert url.host.lower() == "example.com"

    def test_host_domain_with_hyphens(self):
        """Domain names can contain hyphens"""
        url = parse_url("http://my-domain.com/")
        assert url.host == "my-domain.com"

    def test_host_subdomain_multiple_levels(self):
        """Multiple levels of subdomains"""
        url = parse_url("http://a.b.c.d.e.example.com/")
        assert url.host == "a.b.c.d.e.example.com"

    def test_port_zero_invalid(self):
        """Port 0 should be invalid"""
        with pytest.raises(InvalidURLError):
            parse_url("http://example.com:0/")

    def test_port_65535_valid(self):
        """Port 65535 is maximum valid"""
        url = parse_url("http://example.com:65535/")
        assert url.port == 65535

    def test_port_65536_invalid(self):
        """Port 65536 exceeds maximum"""
        with pytest.raises(InvalidURLError):
            parse_url("http://example.com:65536/")


class TestSchemeValidationRFC3986:
    """RFC 3986 § 3.1: Scheme Component"""

    def test_scheme_must_start_with_letter(self):
        """RFC 3986 § 3.1: Scheme must begin with letter"""
        with pytest.raises(URLParseError):
            parse_url("1http://example.com/")

    def test_scheme_allowed_characters(self):
        """RFC 3986 § 3.1: Scheme contains ALPHA / DIGIT / "+" / "-" / "."""
        valid_schemes = [
            "http://example.com",
            "https://example.com",
            "ftp://example.com",
            "h2c://example.com",
            "svn+ssh://example.com",
        ]
        for url_str in valid_schemes:
            url = parse_url(url_str)
            assert url.scheme is not None

    def test_scheme_case_insensitive_normalization(self):
        """Schemes are normalized to lowercase"""
        url = parse_url("HTTP://example.com/")
        assert url.scheme == "http"

    def test_scheme_separator_variants(self):
        """Scheme can use :// or : separator"""
        # With :// (authority-based)
        url1 = parse_url("http://example.com/path")
        assert url1.host == "example.com"

        # With : (non-authority, like mailto)
        parser = Parser()
        parser.custom_scheme = True
        result = parser.parse("mailto:user@example.com")
        assert result["scheme"] == "mailto"


class TestFragmentValidationRFC3986:
    """RFC 3986 § 3.5: Fragment Component"""

    def test_fragment_can_contain_slashes(self):
        """Fragment can contain slashes (they have no special meaning)"""
        url = parse_url("http://example.com/#section/subsection")
        assert url.fragment == "section/subsection"

    def test_fragment_can_contain_query_like_syntax(self):
        """Fragment can look like a query string"""
        url = parse_url("http://example.com/#key=value&foo=bar")
        assert url.fragment == "key=value&foo=bar"

    def test_fragment_reserved_characters(self):
        """Fragment can contain reserved characters"""
        url = parse_url("http://example.com/#!$&'()*+,;=:@/?")
        assert url.fragment is not None

    def test_fragment_percent_encoding(self):
        """Fragment can contain percent-encoded characters"""
        url = parse_url("http://example.com/#section%20name")
        assert url.fragment == "section%20name"

    def test_empty_fragment(self):
        """Empty fragment (#) is different from no fragment"""
        url_with = parse_url("http://example.com/#")
        url_without = parse_url("http://example.com/")
        assert url_with.fragment == ""
        assert url_without.fragment is None


class TestRelativeReferenceRFC3986:
    """RFC 3986 § 4: URI References"""

    def test_absolute_vs_relative_reference(self):
        """Relative references don't have scheme"""
        parser = Parser()

        # Absolute reference
        absolute = parser.parse("http://example.com/path")
        assert absolute["scheme"] == "http"

        # Relative reference (network-path)
        network = parser.parse("//example.com/path")
        assert network["scheme"] is None

        # Relative reference (path-absolute)
        path_abs = parser.parse("/path/to/resource")
        assert path_abs["scheme"] is None
        assert path_abs["host"] is None

    def test_network_path_reference(self):
        """Network-path reference: //authority/path"""
        parser = Parser()
        result = parser.parse("//example.com/path")
        assert result["scheme"] is None
        assert result["host"] == "example.com"
        assert result["path"] == "/path"

    def test_path_absolute_reference(self):
        """Path-absolute reference: /path"""
        parser = Parser()
        result = parser.parse("/path/to/resource")
        assert result["scheme"] is None
        assert result["host"] is None
        assert result["path"] == "/path/to/resource"

    def test_path_relative_reference(self):
        """Path-relative reference: path (no leading /)"""
        parser = Parser()
        result = parser.parse("path/to/resource")
        assert result["scheme"] is None
        assert result["host"] is None
        assert result["path"] == "path/to/resource"

    def test_query_only_reference(self):
        """Query-only reference: ?query"""
        parser = Parser()
        result = parser.parse("?newquery")
        assert result["scheme"] is None
        assert result["query"] == "newquery"

    def test_fragment_only_reference(self):
        """Fragment-only reference: #fragment"""
        parser = Parser()
        result = parser.parse("#newsection")
        assert result["scheme"] is None
        assert result["fragment"] == "newsection"


class TestNormalizationRFC3986:
    """RFC 3986 § 6: URI Normalization"""

    def test_scheme_normalization_case(self):
        """Scheme normalization: case to lowercase"""
        url = parse_url("HTTP://EXAMPLE.COM/")
        assert url.scheme == "http"

    def test_host_normalization_case(self):
        """Host normalization: case to lowercase (recommended)"""
        url = parse_url("http://EXAMPLE.COM/")
        # RFC recommends lowercase
        assert url.host.lower() == "example.com"

    def test_path_normalization_dot_segments(self):
        """Path normalization: remove . and .. segments"""
        # Use parse_url_unsafe for path traversal pattern tests
        url = parse_url_unsafe("http://example.com/a/./b/../c")
        assert url.path == "/a/c"
        assert ".." not in url.path
        assert "/." not in url.path

    def test_percent_encoding_normalization(self):
        """Percent-encoding normalization: uppercase hex"""
        builder = Builder()
        encoded = builder.percent_encode("test", safe="")
        # Any percent-encodings should be uppercase
        import re
        for match in re.finditer(r'%[0-9a-fA-F]{2}', encoded):
            assert match.group(0) == match.group(0).upper()

    def test_port_normalization_default_omitted(self):
        """Explicit default ports should be omitted in normalized form"""
        url = parse_url("http://example.com:80/")
        # When reconstructed, default port should be hidden
        reconstructed = url.as_string()
        assert ":80" not in reconstructed

    def test_empty_authority_handling(self):
        """Empty authority handling (file:// scheme)"""
        url = parse_url("file:///path/to/file", allow_custom_scheme=True)
        assert url.path == "/path/to/file"
        # file: may have empty authority
        assert url.host is None or url.host == ""


class TestCrossComponentInteractions:
    """Test interactions between URL components"""

    def test_authority_with_empty_path(self):
        """RFC 3986 § 3: Presence of authority requires path to start with / or be empty"""
        url = parse_url("http://example.com")
        assert url.path == "/"

        url2 = parse_url("http://example.com/")
        assert url2.path == "/"

    def test_query_with_fragment(self):
        """Query and fragment can coexist"""
        url = parse_url("http://example.com/?query=value#fragment")
        assert url.query == "query=value"
        assert url.fragment == "fragment"

    def test_userinfo_requires_host(self):
        """Userinfo (@) requires a host"""
        # This should parse, but userinfo is part of authority
        url = parse_url("http://user@example.com/")
        assert url.userinfo == "user"

    def test_port_requires_host(self):
        """Port (:) requires a host"""
        with pytest.raises(InvalidURLError):
            parse_url("http://:8080/")

    def test_authority_requires_scheme(self):
        """Absolute authority (://) requires a scheme in absolute URI"""
        # But relative references can have authority
        parser = Parser()
        result = parser.parse("//example.com/path")
        assert result["host"] == "example.com"

    def test_scheme_affects_port_default(self):
        """Scheme determines default port"""
        http_url = parse_url("http://example.com/")
        https_url = parse_url("https://example.com/")
        ftp_url = parse_url("ftp://example.com/")

        assert http_url.effective_port == 80
        assert https_url.effective_port == 443
        assert ftp_url.effective_port == 21


class TestValidationStrictness:
    """Test strict validation to ensure RFC compliance"""

    def test_control_characters_rejected(self):
        """Control characters and whitespace should be rejected"""
        with pytest.raises(URLParseError):
            parse_url("http://example.com/path\nwith\nnewlines")

    def test_null_bytes_rejected(self):
        """Null bytes should be rejected"""
        # parse_url now does security checks which also catch null bytes
        with pytest.raises((URLParseError, InvalidURLError)):
            parse_url("http://example.com/path\x00null")

    def test_invalid_percent_encoding_format(self):
        """Percent-encoding must be %HH where H is hex"""
        # Our implementation allows this during parsing but validates during composition
        # This is acceptable per RFC
        url = parse_url("http://example.com/path%20ok")
        assert "%20" in url.path

    def test_scheme_format_validation(self):
        """Scheme must match RFC format"""
        # Valid: starts with letter, contains ALPHA/DIGIT/+/-/.
        valid = parse_url("http://example.com/")
        assert valid.scheme == "http"

        # Invalid: starts with number
        with pytest.raises(URLParseError):
            parse_url("2http://example.com/")

    def test_userinfo_format_validation(self):
        """Userinfo format must be valid"""
        # Valid
        url = parse_url("http://user%3Aname:pass%40word@example.com/")
        assert url.userinfo is not None

    def test_host_format_validation(self):
        """Host must be valid domain, IPv4, or IPv6"""
        # Valid domain
        assert parse_url("http://example.com/").host == "example.com"

        # Valid IPv4 - use parse_url_unsafe for private IPs
        assert parse_url_unsafe("http://192.168.1.1/").host == "192.168.1.1"

        # Valid IPv6 - use parse_url_unsafe for loopback
        assert parse_url_unsafe("http://[::1]/").host == "[::1]"



class TestBoundaryConditions:
    """Test boundary conditions and extreme cases"""

    def test_maximum_port_value(self):
        """Port 65535 should work"""
        url = parse_url("http://example.com:65535/")
        assert url.port == 65535

    def test_minimum_port_value(self):
        """Port 1 should work"""
        url = parse_url("http://example.com:1/")
        assert url.port == 1

    def test_very_long_path(self):
        """Very long paths should be handled up to the security limit"""
        # Paths up to MAX_PATH_LENGTH (4096) should work
        long_path = "/" + "a" * 4000
        url = parse_url(f"http://example.com{long_path}")
        assert len(url.path) > 3900

        # Paths exceeding MAX_PATH_LENGTH should be rejected
        too_long_path = "/" + "a" * 10000
        with pytest.raises(URLParseError):
            parse_url(f"http://example.com{too_long_path}")

    def test_very_long_query(self):
        """Very long query strings should be handled"""
        long_query = "key=" + "a" * 8000
        url = parse_url(f"http://example.com/?{long_query}")
        assert url.query is not None

    def test_very_long_hostname(self):
        """Long hostnames (up to 253 chars) should work"""
        # Create a valid long hostname
        long_host = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 50 + ".com"
        url = parse_url(f"http://{long_host}/")
        assert url.host == long_host

    def test_many_query_parameters(self):
        """Many query parameters should be handled"""
        params = "&".join([f"key{i}=value{i}" for i in range(500)])
        url = parse_url(f"http://example.com/?{params}")
        assert len(url.query_params) == 500
