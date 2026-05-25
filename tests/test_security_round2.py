"""Security improvements tests - Round 2.

Tests for:
- #1: Open redirect detection
- #2: URL canonicalization
- #4: DNS rebinding protection (behind check_dns flag)
- #5: Cache management
- #6: Double-encoding detection
- #7: Secure defaults (parse_url is secure by default)
- #8: Path traversal detection
- #9: Semantic URL comparison
- #10: Audit logging
"""
import pytest
from unittest.mock import Mock, patch

from src.urlps import (
    parse_url,
    parse_url_unsafe,
    InvalidURLError,
    URLParseError,
)
from src.urlps.constants import PASSWORD_MASK
from src.urlps._security import (
    is_open_redirect_risk,
    check_dns_rebinding,
    has_double_encoding,
    has_mixed_scripts,
    has_path_traversal,
)
from src.urlps._validation import Validator


class TestOpenRedirectDetection:
    """Tests for open redirect detection (improvement #1 round 2)."""

    def test_backslash_detected(self):
        """Backslash in path should be detected as redirect risk."""
        assert is_open_redirect_risk("\\\\evil.com")
        assert is_open_redirect_risk("/path\\to\\file")

    def test_double_slash_start_detected(self):
        """Double slash at start should be detected."""
        assert is_open_redirect_risk("//evil.com/path")

    def test_triple_slash_detected(self):
        """Triple slash should be detected."""
        assert is_open_redirect_risk("///evil.com")

    def test_normal_path_safe(self):
        """Normal paths should not be flagged."""
        assert not is_open_redirect_risk("/normal/path")
        assert not is_open_redirect_risk("/path/to/resource")
        assert not is_open_redirect_risk("/")

    def test_parse_url_rejects_redirect_risk(self):
        """parse_url should reject open redirect patterns."""
        # Path with backslash
        with pytest.raises(InvalidURLError, match="open redirect"):
            parse_url("http://example.com/path\\to\\evil")


class TestURLCanonicalization:
    """Tests for URL canonicalization (improvement #2 round 2)."""

    def test_scheme_lowercase(self):
        """Scheme should be normalized to lowercase."""
        url = parse_url("HTTP://EXAMPLE.COM/path")
        canonical = url.canonicalize()
        assert canonical.scheme == "http"

    def test_host_lowercase(self):
        """Host should be normalized to lowercase."""
        url = parse_url("http://EXAMPLE.COM/path")
        canonical = url.canonicalize()
        assert canonical.host == "example.com"

    def test_default_port_removed(self):
        """Default port should be removed."""
        url = parse_url("http://example.com:80/path")
        canonical = url.canonicalize()
        assert canonical.port is None

    def test_non_default_port_kept(self):
        """Non-default port should be preserved."""
        url = parse_url("http://example.com:8080/path")
        canonical = url.canonicalize()
        assert canonical.port == 8080

    def test_query_params_sorted(self):
        """Query parameters should be sorted."""
        url = parse_url("http://example.com/path?z=1&a=2&m=3")
        canonical = url.canonicalize()
        assert canonical.query == "a=2&m=3&z=1"



class TestPasswordMasking:
    """Tests for password masking (improvement #3 round 2)."""

    def test_password_masked_in_as_string(self):
        """Password should be masked when requested."""
        url = parse_url("http://user:secret@example.com/path")
        masked = url.as_string(mask_password=True)
        assert "secret" not in masked
        assert PASSWORD_MASK in masked
        assert "user:" in masked

    def test_password_not_masked_by_default(self):
        """Password should not be masked by default."""
        url = parse_url("http://user:secret@example.com/path")
        normal = url.as_string()
        assert "secret" in normal

    def test_no_password_unchanged(self):
        """URL without password should be unchanged."""
        url = parse_url("http://user@example.com/path")
        masked = url.as_string(mask_password=True)
        assert "user@" in masked

    def test_no_userinfo_unchanged(self):
        """URL without userinfo should be unchanged."""
        url = parse_url("http://example.com/path")
        masked = url.as_string(mask_password=True)
        assert masked == "http://example.com/path"


class TestDNSRebindingProtection:
    """Tests for DNS rebinding protection (improvement #4 round 2)."""

    def test_ip_address_direct_check(self):
        """Direct IP addresses should be checked without DNS."""
        assert check_dns_rebinding("8.8.8.8")
        assert not check_dns_rebinding("127.0.0.1")
        assert not check_dns_rebinding("192.168.1.1")
        assert not check_dns_rebinding("10.0.0.1")

    def test_check_dns_flag_separate_from_strict(self):
        """check_dns should work independently of strict mode."""
        # parse_url is now always strict - use parse_url_unsafe for non-strict
        url = parse_url_unsafe("http://google.com/", strict=True)
        assert url.host == "google.com"

        # check_dns is a separate flag
        url2 = parse_url_unsafe("http://google.com/", check_dns=False)
        assert url2.host == "google.com"

    @patch('src.urlps._security.dns_guard.socket.getaddrinfo')
    def test_dns_resolves_to_private_blocked(self, mock_getaddrinfo):
        """DNS that resolves to private IP should be blocked with check_dns."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('127.0.0.1', 0))  # Returns loopback
        ]

        assert not check_dns_rebinding("evil.example.com")

    @patch('src.urlps._security.dns_guard.socket.getaddrinfo')
    def test_dns_resolves_to_public_allowed(self, mock_getaddrinfo):
        """DNS that resolves to public IP should be allowed."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('93.184.216.34', 0))  # example.com IP
        ]

        assert check_dns_rebinding("example.com", enforce_rate_limit=False)

    def test_dns_resolution_failure_treated_as_unsafe(self):
        """DNS resolution failure should be treated as unsafe."""
        assert not check_dns_rebinding("definitely-not-a-real-domain-12345.invalid")


class TestCacheManagement:
    """Tests for cache management (improvement #5 round 2)."""

    def test_get_cache_info(self):
        """Should return cache statistics."""
        # Trigger some cache entries
        Validator.is_valid_host("example.com")
        Validator.is_valid_scheme("http")

        info = Validator.get_cache_info()

        assert 'is_valid_host' in info
        assert 'is_valid_scheme' in info
        assert isinstance(info['is_valid_host'], dict)
        assert 'hits' in info['is_valid_host']
        assert 'misses' in info['is_valid_host']

    def test_clear_caches(self):
        """Should clear all caches and return previous sizes."""
        # Populate caches
        Validator.is_valid_host("example.com")
        Validator.is_valid_scheme("http")

        previous = Validator.clear_caches()

        assert isinstance(previous, dict)
        assert 'is_valid_host' in previous

        # Verify caches are cleared
        info = Validator.get_cache_info()
        assert info['is_valid_host']['currsize'] == 0


class TestDoubleEncodingDetection:
    """Tests for double-encoding detection (improvement #6 round 2)."""

    def test_double_encoded_slash(self):
        """Should detect double-encoded slash (%252F)."""
        assert has_double_encoding("%252F")  # %2F encoded

    def test_double_encoded_dot(self):
        """Should detect double-encoded dot (%252E)."""
        assert has_double_encoding("%252E")  # %2E encoded

    def test_single_encoding_safe(self):
        """Single encoding should not be flagged."""
        assert not has_double_encoding("%2F")
        assert not has_double_encoding("%2E")

    def test_no_encoding_safe(self):
        """Plain text should not be flagged."""
        assert not has_double_encoding("/path/to/file")
        assert not has_double_encoding("normal text")

    def test_parse_url_rejects_double_encoding(self):
        """parse_url should reject double-encoded URLs."""
        with pytest.raises(InvalidURLError, match="double-encoded"):
            parse_url("http://example.com/path%252Ftraversal")


class TestSecureDefaults:
    """Tests for secure defaults - parse_url is secure by default (improvement #7 round 2)."""

    def test_strict_mode_enabled_by_default(self):
        """Strict mode should be enabled."""
        with pytest.raises(InvalidURLError):
            parse_url("http://127.0.0.1/")

    def test_urls_are_immutable(self):
        """URLs are immutable and hashable."""
        url = parse_url("http://example.com/path")
        # URLs are always immutable - can be hashed
        assert hash(url) is not None

    def test_rejects_ssrf_risks(self):
        """Should reject SSRF risks."""
        with pytest.raises(InvalidURLError):
            parse_url("http://localhost/")

        with pytest.raises(InvalidURLError):
            parse_url("http://192.168.1.1/")

    def test_rejects_path_traversal(self):
        """Should reject path traversal."""
        with pytest.raises(InvalidURLError, match="path traversal"):
            parse_url("http://example.com/path/../../../etc/passwd")

    def test_rejects_mixed_scripts(self):
        """Should reject mixed scripts in host."""
        # Test the validator directly first
        cyrillic_a = '\u0430'  # Cyrillic small letter a
        mixed_host = f"ex{cyrillic_a}mple"
        assert has_mixed_scripts(mixed_host), "Validator should detect mixed scripts"

        # parse_url checks mixed scripts on original host before IDNA encoding
        with pytest.raises(InvalidURLError, match="mixed Unicode scripts"):
            parse_url(f"http://{mixed_host}.com/")

    def test_accepts_safe_urls(self):
        """Should accept safe URLs."""
        url = parse_url("http://example.com/path?query=value#fragment")
        assert url.host == "example.com"
        assert url.path == "/path"


class TestPathTraversalDetection:
    """Tests for path traversal detection (improvement #8 round 2)."""

    def test_dot_dot_detected(self):
        """Should detect .. in path."""
        assert has_path_traversal("../../../etc/passwd")
        assert has_path_traversal("/path/../secret")

    def test_encoded_dot_dot_detected(self):
        """Should detect encoded .. (%2e%2e)."""
        assert has_path_traversal("%2e%2e/etc/passwd")
        assert has_path_traversal("%2E%2E/etc/passwd")

    def test_null_byte_detected(self):
        """Should detect null byte injection."""
        assert has_path_traversal("/path\x00.jpg")

    def test_normal_path_safe(self):
        """Normal paths should not be flagged."""
        assert not has_path_traversal("/normal/path/to/file")
        assert not has_path_traversal("/path/file.txt")


class TestSemanticURLComparison:
    """Tests for semantic URL comparison (improvement #9 round 2)."""

    def test_case_insensitive_scheme(self):
        """Different case schemes should be semantically equal."""
        url1 = parse_url("HTTP://example.com/path")
        url2 = parse_url("http://example.com/path")

        assert url1.is_semantically_equal(url2)

    def test_case_insensitive_host(self):
        """Different case hosts should be semantically equal."""
        url1 = parse_url("http://EXAMPLE.COM/path")
        url2 = parse_url("http://example.com/path")

        assert url1.is_semantically_equal(url2)

    def test_default_port_equivalence(self):
        """URLs with/without default port should be semantically equal."""
        url1 = parse_url("http://example.com:80/path")
        url2 = parse_url("http://example.com/path")

        assert url1.is_semantically_equal(url2)

    def test_different_ports_not_equal(self):
        """Different non-default ports should not be equal."""
        url1 = parse_url("http://example.com:8080/path")
        url2 = parse_url("http://example.com:9090/path")

        assert not url1.is_semantically_equal(url2)

    def test_different_paths_not_equal(self):
        """Different paths should not be equal."""
        url1 = parse_url("http://example.com/path1")
        url2 = parse_url("http://example.com/path2")

        assert not url1.is_semantically_equal(url2)

    def test_query_order_ignored(self):
        """Query parameter order should not affect equality."""
        url1 = parse_url("http://example.com/path?a=1&b=2")
        url2 = parse_url("http://example.com/path?b=2&a=1")

        # Both should have query pairs parsed
        assert len(url1.query_params) == 2
        assert len(url2.query_params) == 2

        # Canonical form should sort them the same
        canonical1 = url1.canonicalize()
        canonical2 = url2.canonicalize()

        assert canonical1.query == canonical2.query
        assert url1.is_semantically_equal(url2)
