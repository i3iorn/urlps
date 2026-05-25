"""Tests for IPv6 zone identifier validation."""
import pytest
from urlps import parse_url, InvalidURLError
from urlps._security import is_malicious_ipv6_zone_id


class TestIPv6ZoneIdentifier:
    """Test IPv6 zone identifier validation."""

    def test_valid_zone_identifiers(self):
        """Valid zone identifiers should be allowed."""
        assert not is_malicious_ipv6_zone_id("[fe80::1%25eth0]")
        assert not is_malicious_ipv6_zone_id("[fe80::1%25en0]")
        assert not is_malicious_ipv6_zone_id("[fe80::1%251]")
        assert not is_malicious_ipv6_zone_id("[fe80::1%25wlan0]")
        assert not is_malicious_ipv6_zone_id("[fe80::1%25lo]")
        assert not is_malicious_ipv6_zone_id("[fe80::1%25eth0-1]")
        assert not is_malicious_ipv6_zone_id("[fe80::1%25eth0.1]")
        assert not is_malicious_ipv6_zone_id("[fe80::1%25eth0~1]")

    def test_malicious_zone_identifiers(self):
        """Malicious zone identifiers should be detected."""
        assert is_malicious_ipv6_zone_id("[fe80::1%25eth0;rm -rf /]")
        assert is_malicious_ipv6_zone_id("[fe80::1%25eth0|nc]")
        assert is_malicious_ipv6_zone_id("[fe80::1%25eth0&whoami]")
        assert is_malicious_ipv6_zone_id("[fe80::1%25eth0$USER]")
        assert is_malicious_ipv6_zone_id("[fe80::1%25eth0`id`]")
        assert is_malicious_ipv6_zone_id("[fe80::1%25eth0(test)]")
        assert is_malicious_ipv6_zone_id("[fe80::1%25eth0{test}]")
        assert is_malicious_ipv6_zone_id("[fe80::1%25eth0<test>]")
        assert is_malicious_ipv6_zone_id("[fe80::1%25eth0/etc/passwd]")
        assert is_malicious_ipv6_zone_id("[fe80::1%25eth0\\test]")

    def test_empty_zone_identifier(self):
        """Empty zone identifier should be detected."""
        assert is_malicious_ipv6_zone_id("[fe80::1%25]")

    def test_non_ipv6_addresses(self):
        """Non-IPv6 addresses should not trigger false positives."""
        assert not is_malicious_ipv6_zone_id("example.com")
        assert not is_malicious_ipv6_zone_id("192.168.1.1")
        assert not is_malicious_ipv6_zone_id("fe80::1")  # No zone ID

    def test_edge_cases(self):
        """Test edge cases."""
        assert not is_malicious_ipv6_zone_id("")
        assert not is_malicious_ipv6_zone_id(None)
        assert not is_malicious_ipv6_zone_id("[fe80::1]")  # No zone ID
        assert not is_malicious_ipv6_zone_id("not-ipv6%25test")  # Missing brackets

    def test_parse_url_blocks_malicious_zone_ids(self):
        """parse_url should block malicious IPv6 zone identifiers."""
        with pytest.raises(InvalidURLError, match="zone identifier"):
            parse_url("http://[fe80::1%25eth0;whoami]/")

        with pytest.raises(InvalidURLError, match="zone identifier"):
            parse_url("http://[fe80::1%25eth0|nc]/")

        with pytest.raises(InvalidURLError):
            # This will fail during parsing due to invalid format
            parse_url("http://[fe80::1%25eth0{test}]/")

    def test_valid_zone_ids_pass(self):
        """Valid IPv6 zone identifiers should parse successfully."""
        # Note: These will fail SSRF checks, so use parse_url_unsafe
        from urlps import parse_url_unsafe

        url = parse_url_unsafe("http://[fe80::1%25eth0]/")
        assert url.host == "[fe80::1%25eth0]"

        url2 = parse_url_unsafe("http://[fe80::1%25en0]/path")
        assert url2.host == "[fe80::1%25en0]"


class TestRealWorldIPv6Scenarios:
    """Test real-world IPv6 attack scenarios."""

    def test_command_injection_via_zone_id(self):
        """Command injection attempts via zone ID should be blocked."""
        with pytest.raises(InvalidURLError):
            parse_url("http://[fe80::1%25eth0;curl evil.com]/")

        with pytest.raises(InvalidURLError):
            parse_url("http://[fe80::1%25eth0|bash]/")

    def test_path_traversal_via_zone_id(self):
        """Path traversal via zone ID should be blocked."""
        with pytest.raises(InvalidURLError):
            parse_url("http://[fe80::1%25path*traversal]/")

    def test_ssrf_internal_interface_access(self):
        """SSRF via link-local IPv6 should be blocked (separate from zone ID check)."""
        # This would be blocked by SSRF checks, not zone ID checks
        with pytest.raises(InvalidURLError):
            parse_url("http://[fe80::1]/")

    def test_unencoded_percent_in_zone_id(self):
        """Unencoded % in zone ID should be handled."""
        assert is_malicious_ipv6_zone_id("[fe80::1%eth0;test]")


class TestZoneIDFormats:
    """Test different zone ID encoding formats."""

    def test_percent_encoded_zone_id(self):
        """Properly percent-encoded zone IDs should be validated."""
        assert not is_malicious_ipv6_zone_id("[fe80::1%25eth0]")
        assert not is_malicious_ipv6_zone_id("[fe80::1%251]")

    def test_unencoded_zone_id(self):
        """Unencoded zone IDs (with raw %) should be validated."""
        # Some parsers might pass through unencoded %
        assert is_malicious_ipv6_zone_id("[fe80::1%eth0;test]")

    def test_numeric_zone_ids(self):
        """Numeric zone IDs should be allowed."""
        assert not is_malicious_ipv6_zone_id("[fe80::1%251]")
        assert not is_malicious_ipv6_zone_id("[fe80::1%2512]")
        assert not is_malicious_ipv6_zone_id("[fe80::1%25123]")
