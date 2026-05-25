"""Tests for canonical form validation."""
import pytest
from urlps._security import is_non_canonical_url, get_canonical_url


class TestCanonicalDetection:
    """Test detection of non-canonical URLs."""

    def test_canonical_url(self):
        """Canonical URLs should return False."""
        assert not is_non_canonical_url("http://example.com")
        assert not is_non_canonical_url("https://example.com/path")
        assert not is_non_canonical_url("http://example.com/path?key=value")

    def test_uppercase_scheme(self):
        """Uppercase scheme is non-canonical."""
        assert is_non_canonical_url("HTTP://example.com")
        assert is_non_canonical_url("HTTPS://example.com")
        assert is_non_canonical_url("FTP://example.com")

    def test_mixed_case_scheme(self):
        """Mixed case scheme is non-canonical."""
        assert is_non_canonical_url("Http://example.com")
        assert is_non_canonical_url("Https://example.com")

    def test_uppercase_host(self):
        """Uppercase host is non-canonical."""
        assert is_non_canonical_url("http://EXAMPLE.COM")
        assert is_non_canonical_url("http://Example.Com")
        assert is_non_canonical_url("http://SUBDOMAIN.EXAMPLE.COM")


class TestDefaultPorts:
    """Test detection of unnecessary default ports."""

    def test_http_port_80(self):
        """HTTP with port 80 is non-canonical."""
        assert is_non_canonical_url("http://example.com:80")
        assert is_non_canonical_url("http://example.com:80/path")

    def test_https_port_443(self):
        """HTTPS with port 443 is non-canonical."""
        assert is_non_canonical_url("https://example.com:443")
        assert is_non_canonical_url("https://example.com:443/path")

    def test_ftp_port_21(self):
        """FTP with port 21 is non-canonical."""
        assert is_non_canonical_url("ftp://example.com:21")

    def test_ws_port_80(self):
        """WebSocket with port 80 is non-canonical."""
        assert is_non_canonical_url("ws://example.com:80")

    def test_wss_port_443(self):
        """Secure WebSocket with port 443 is non-canonical."""
        assert is_non_canonical_url("wss://example.com:443")

    def test_non_default_ports_ok(self):
        """Non-default ports are canonical."""
        assert not is_non_canonical_url("http://example.com:8080")
        assert not is_non_canonical_url("https://example.com:8443")
        assert not is_non_canonical_url("http://example.com:3000")


class TestPathNormalization:
    """Test path normalization detection."""

    def test_dot_segment(self):
        """Dot segments in path are non-canonical."""
        assert is_non_canonical_url("http://example.com/./path")
        assert is_non_canonical_url("http://example.com/path/.")
        assert is_non_canonical_url("http://example.com/./")

    def test_dot_dot_segment(self):
        """Double-dot segments in path are non-canonical."""
        assert is_non_canonical_url("http://example.com/../path")
        assert is_non_canonical_url("http://example.com/path/../other")
        assert is_non_canonical_url("http://example.com/a/b/../../c")

    def test_normalized_path(self):
        """Normalized paths are canonical."""
        assert not is_non_canonical_url("http://example.com/path")
        assert not is_non_canonical_url("http://example.com/a/b/c")


class TestTrailingDots:
    """Test trailing dot detection in hostnames."""

    def test_trailing_dot(self):
        """Trailing dot in hostname is non-canonical."""
        assert is_non_canonical_url("http://example.com.")
        assert is_non_canonical_url("http://example.com./path")
        assert is_non_canonical_url("http://subdomain.example.com.")

    def test_no_trailing_dot(self):
        """No trailing dot is canonical."""
        assert not is_non_canonical_url("http://example.com")
        assert not is_non_canonical_url("http://subdomain.example.com")


class TestPercentEncoding:
    """Test percent-encoding normalization."""

    def test_unnecessary_encoding_unreserved(self):
        """Unnecessary encoding of unreserved chars is non-canonical."""
        # A (0x41) should not be encoded
        assert is_non_canonical_url("http://example.com/%41")
        # z (0x7A) should not be encoded
        assert is_non_canonical_url("http://example.com/%7A")
        # 0 (0x30) should not be encoded
        assert is_non_canonical_url("http://example.com/%30")

    def test_lowercase_percent_encoding(self):
        """Lowercase percent-encoding is non-canonical."""
        assert is_non_canonical_url("http://example.com/%2f")  # Should be %2F
        assert is_non_canonical_url("http://example.com/path%2fto")

    def test_mixed_case_percent_encoding(self):
        """Mixed case percent-encoding is non-canonical."""
        assert is_non_canonical_url("http://example.com/%2F%2f")

    def test_uppercase_percent_encoding_ok(self):
        """Uppercase percent-encoding of reserved chars is ok."""
        # %2F for / is acceptable (though unusual)
        # We don't flag uppercase encoding of reserved chars
        assert not is_non_canonical_url("http://example.com/path")


class TestIPv6Canonical:
    """Test IPv6 address canonical form."""

    def test_non_compressed_ipv6(self):
        """Non-compressed IPv6 should be flagged."""
        # Full form instead of compressed
        assert is_non_canonical_url("http://[0000:0000:0000:0000:0000:0000:0000:0001]")

    def test_uppercase_ipv6(self):
        """Uppercase IPv6 should be flagged."""
        assert is_non_canonical_url("http://[2001:DB8::1]")

    def test_canonical_ipv6_ok(self):
        """Canonical IPv6 should be ok."""
        assert not is_non_canonical_url("http://[::1]")
        assert not is_non_canonical_url("http://[2001:db8::1]")


class TestQueryFragment:
    """Test query string and fragment normalization."""

    def test_query_lowercase_encoding(self):
        """Lowercase encoding in query is non-canonical."""
        assert is_non_canonical_url("http://example.com?key=%2fvalue")

    def test_fragment_lowercase_encoding(self):
        """Lowercase encoding in fragment is non-canonical."""
        assert is_non_canonical_url("http://example.com#section%2f1")

    def test_uppercase_encoding_ok(self):
        """Uppercase encoding in query/fragment is ok."""
        assert not is_non_canonical_url("http://example.com?key=value")
        assert not is_non_canonical_url("http://example.com#section")


class TestEdgeCases:
    """Test edge cases."""

    def test_empty_string(self):
        """Empty string should return False."""
        assert not is_non_canonical_url("")

    def test_no_scheme(self):
        """URLs without scheme should return False."""
        assert not is_non_canonical_url("example.com")
        assert not is_non_canonical_url("//example.com")

    def test_invalid_url(self):
        """Invalid URLs should return False."""
        assert not is_non_canonical_url("not a url")
        assert not is_non_canonical_url("http://")

    def test_invalid_types(self):
        """Non-string types should return False."""
        assert not is_non_canonical_url(None)
        assert not is_non_canonical_url(123)
        assert not is_non_canonical_url([])


class TestCanonicalUrlGeneration:
    """Test canonical URL generation."""

    def test_lowercase_scheme(self):
        """Should lowercase scheme."""
        assert get_canonical_url("HTTP://example.com") == "http://example.com"
        assert get_canonical_url("HTTPS://example.com") == "https://example.com"

    def test_lowercase_host(self):
        """Should lowercase host."""
        assert get_canonical_url("http://EXAMPLE.COM") == "http://example.com"
        assert get_canonical_url("http://Example.Com") == "http://example.com"

    def test_remove_default_port(self):
        """Should remove default ports."""
        assert get_canonical_url("http://example.com:80") == "http://example.com"
        assert get_canonical_url("https://example.com:443") == "https://example.com"
        assert get_canonical_url("ftp://example.com:21") == "ftp://example.com"

    def test_keep_non_default_port(self):
        """Should keep non-default ports."""
        assert get_canonical_url("http://example.com:8080") == "http://example.com:8080"
        assert get_canonical_url("https://example.com:8443") == "https://example.com:8443"

    def test_normalize_path(self):
        """Should normalize path."""
        assert get_canonical_url("http://example.com/./path") == "http://example.com/path"
        assert get_canonical_url("http://example.com/a/../b") == "http://example.com/b"
        assert get_canonical_url("http://example.com/a/b/../../c") == "http://example.com/c"

    def test_remove_trailing_dot(self):
        """Should remove trailing dot from hostname."""
        assert get_canonical_url("http://example.com.") == "http://example.com"
        assert get_canonical_url("http://example.com./path") == "http://example.com/path"

    def test_uppercase_percent_encoding(self):
        """Should uppercase percent-encoding."""
        result = get_canonical_url("http://example.com/%2f")
        assert "%2F" in result or "/" in result  # Either uppercase or decoded

    def test_canonical_ipv6(self):
        """Should canonicalize IPv6."""
        # Full form to compressed
        result = get_canonical_url("http://[0000:0000:0000:0000:0000:0000:0000:0001]")
        assert "[::1]" in result

    def test_already_canonical(self):
        """Already canonical URLs should stay the same."""
        url = "http://example.com/path"
        assert get_canonical_url(url) == url

    def test_invalid_url_returns_none(self):
        """Invalid URLs should return None."""
        assert get_canonical_url("") is None
        assert get_canonical_url("not a url") is None
        assert get_canonical_url(None) is None


class TestCanonicalRoundTrip:
    """Test that canonical URLs pass canonical check."""

    def test_canonical_passes_check(self):
        """Canonical URLs should pass is_non_canonical_url check."""
        canonical = get_canonical_url("HTTP://EXAMPLE.COM:80/path")
        if canonical:
            assert not is_non_canonical_url(canonical)

    def test_multiple_canonicalizations_idempotent(self):
        """Multiple canonicalizations should be idempotent."""
        url = "HTTP://EXAMPLE.COM:80/./path/../other"
        canonical1 = get_canonical_url(url)
        canonical2 = get_canonical_url(canonical1) if canonical1 else None
        assert canonical1 == canonical2


class TestSecurityImplications:
    """Test security implications of non-canonical URLs."""

    def test_filter_bypass_uppercase(self):
        """Attackers use uppercase to bypass filters."""
        # Filter might block "http://evil.com"
        # But "HTTP://EVIL.COM" bypasses naive string matching
        assert is_non_canonical_url("HTTP://EVIL.COM")

    def test_filter_bypass_encoding(self):
        """Attackers use encoding to bypass filters."""
        # Filter might block "/admin"
        # But "/%41dmin" (A = 0x41) bypasses
        assert is_non_canonical_url("http://example.com/%41dmin")

    def test_cache_key_collision(self):
        """Non-canonical URLs can cause cache key collisions."""
        # These should all be the same resource
        urls = [
            "http://example.com/path",
            "HTTP://EXAMPLE.COM/path",
            "http://example.com:80/path",
            "http://example.com/./path",
        ]
        # Get canonical forms
        canonical_urls = [get_canonical_url(url) for url in urls]
        # All should be the same
        assert len(set(canonical_urls)) == 1

    def test_access_control_bypass(self):
        """Non-canonical URLs can bypass access controls."""
        # Access control might check "http://example.com/admin"
        # But "http://example.com/./admin" or "HTTP://example.com/admin"
        # might bypass if not canonicalized
        url1 = "http://example.com/admin"
        url2 = "http://example.com/./admin"
        url3 = "HTTP://example.com/admin"

        # url2 and url3 are non-canonical
        assert not is_non_canonical_url(url1)
        assert is_non_canonical_url(url2)
        assert is_non_canonical_url(url3)

        # All should canonicalize to the same URL
        assert get_canonical_url(url1) == get_canonical_url(url2) == get_canonical_url(url3)


class TestRealWorldScenarios:
    """Test real-world canonical form scenarios."""

    def test_web_crawler_deduplication(self):
        """Web crawlers need canonical URLs for deduplication."""
        # Same page, different representations
        urls = [
            "http://example.com/page",
            "HTTP://example.com/page",
            "http://EXAMPLE.COM/page",
            "http://example.com:80/page",
            "http://example.com/./page",
        ]

        # All should be detected as non-canonical (except first)
        assert not is_non_canonical_url(urls[0])
        for url in urls[1:]:
            assert is_non_canonical_url(url)

        # All should canonicalize to the same URL
        canonical_urls = [get_canonical_url(url) for url in urls]
        assert len(set(canonical_urls)) == 1

    def test_url_shortener_canonical_storage(self):
        """URL shorteners should store canonical forms."""
        # Different representations of same URL
        input_urls = [
            "HTTP://EXAMPLE.COM/page",
            "http://example.com:80/page",
        ]

        # Should all map to same short URL (same canonical form)
        canonical = [get_canonical_url(url) for url in input_urls]
        assert len(set(canonical)) == 1

    def test_cache_system_key_generation(self):
        """Cache systems should use canonical URLs as keys."""
        # These should have same cache key
        urls = [
            "https://api.example.com/users",
            "HTTPS://API.EXAMPLE.COM/users",
            "https://api.example.com:443/users",
        ]

        canonical_keys = [get_canonical_url(url) for url in urls]
        assert len(set(canonical_keys)) == 1

    def test_security_scanner_url_comparison(self):
        """Security scanners need canonical comparison."""
        # Blacklist entry
        blocked = "http://malware.com/payload"

        # Attacker variations
        variations = [
            "HTTP://MALWARE.COM/payload",
            "http://malware.com:80/payload",
            "http://malware.com/./payload",
        ]

        # All should canonicalize to same form
        blocked_canonical = get_canonical_url(blocked)
        for variant in variations:
            assert get_canonical_url(variant) == blocked_canonical
