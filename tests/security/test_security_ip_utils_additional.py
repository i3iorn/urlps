"""Additional security IP utility tests."""

from __future__ import annotations


class TestIsSsrfRiskTrailingDot:
    """Regression tests for the trailing-dot private-IP bypass.

    A bare hostname with a trailing dot (``evil.com.``) was normalized before
    every check in 1.0.0 so it couldn't slip an allowlist. The same
    normalization was missing for numeric IP-literal forms in
    ``is_ssrf_risk`` -- every IP-literal branch parsed the raw ``host``
    string instead of the trailing-dot-stripped ``host_lower`` that only the
    hostname-blocklist branch used.
    """

    def test_private_ipv4_with_trailing_dot_is_risky(self):
        from urlps._security.ip_utils import is_ssrf_risk

        assert is_ssrf_risk("10.0.0.5.") is True
        assert is_ssrf_risk("192.168.1.1.") is True
        assert is_ssrf_risk("127.0.0.1.") is True

    def test_obfuscated_ipv4_with_trailing_dot_is_risky(self):
        from urlps._security.ip_utils import is_ssrf_risk

        # Decimal and octal/hex obfuscated spellings of 127.0.0.1.
        assert is_ssrf_risk("2130706433.") is True
        assert is_ssrf_risk("0177.0.0.1.") is True

    def test_public_ip_with_trailing_dot_stays_safe(self):
        from urlps._security.ip_utils import is_ssrf_risk

        assert is_ssrf_risk("93.184.216.34.") is False


class TestSecurityPrivateChecks:
    def test_check_ipv6_private_invalid_address(self):
        """Lines 80-81: ValueError in _check_ipv6_private returns False."""
        from urlps._security.ip_utils import _check_ipv6_private

        result = _check_ipv6_private("[not_a_valid_ipv6]")
        assert result is False

    def test_check_ipv6_private_loopback(self):
        """_check_ipv6_private returns True for loopback ::1."""
        from urlps._security.ip_utils import _check_ipv6_private

        result = _check_ipv6_private("[::1]")
        assert result is True

    def test_is_octal_hex_ip_private_valid_octal(self):
        """Lines 151-152: try block in _is_octal_hex_ip_private succeeds."""
        from urlps._security.ip_utils import _is_octal_hex_ip_private

        # 0177 = 127 in octal -> 127.0.0.1 is loopback
        result = _is_octal_hex_ip_private("0177.0.0.1")
        assert result is True

    def test_is_octal_hex_ip_private_hex(self):
        """_is_octal_hex_ip_private with hex octet."""
        from urlps._security.ip_utils import _is_octal_hex_ip_private

        # 0x7f = 127 hex -> 127.0.0.1 is loopback
        result = _is_octal_hex_ip_private("0x7f.0x0.0x0.0x1")
        assert result is True

    def test_check_resolved_ips_safe_invalid_ip_fails_closed(self):
        """An unparseable resolved address is unsafe, not skippable."""
        from urlps._security.ip_utils import _check_resolved_ips_safe

        addr_info = [(2, 1, 6, "", ("invalid_ip_string", 80))]
        assert _check_resolved_ips_safe(addr_info) is False

    def test_check_resolved_ips_safe_empty_fails_closed(self):
        """No addresses means nothing was verified, which is not "safe"."""
        from urlps._security.ip_utils import _check_resolved_ips_safe

        assert _check_resolved_ips_safe([]) is False

    def test_check_resolved_ips_safe_accepts_public_addresses(self):
        from urlps._security.ip_utils import _check_resolved_ips_safe

        addr_info = [(2, 1, 6, "", ("93.184.215.14", 80))]
        assert _check_resolved_ips_safe(addr_info) is True

    def test_verify_connection_safe_empty_addr_info_fails_closed(self):
        """Being unable to determine the peer is not the same as it being safe."""
        from urlps._security.ip_utils import _verify_connection_safe

        assert _verify_connection_safe([], 1.0) is False

    def test_is_private_ip_non_string(self):
        """Line 197: is_private_ip with non-string returns False."""
        from urlps._security import is_private_ip

        # Call the underlying function directly to bypass cache type-checking
        result = is_private_ip.__wrapped__(123)
        assert result is False

    def test_is_private_ip_non_string_none(self):
        """is_private_ip with None returns False."""
        from urlps._security import is_private_ip

        result = is_private_ip.__wrapped__(None)
        assert result is False
