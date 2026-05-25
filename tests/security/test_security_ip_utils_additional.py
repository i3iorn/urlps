"""Additional security IP utility tests."""

from __future__ import annotations

class TestSecurityPrivateChecks:
    def test_check_ipv6_private_invalid_address(self):
        """Lines 80-81: ValueError in _check_ipv6_private returns False."""
        from src.urlps._security.ip_utils import _check_ipv6_private
        result = _check_ipv6_private("[not_a_valid_ipv6]")
        assert result is False

    def test_check_ipv6_private_loopback(self):
        """_check_ipv6_private returns True for loopback ::1."""
        from src.urlps._security.ip_utils import _check_ipv6_private
        result = _check_ipv6_private("[::1]")
        assert result is True

    def test_is_octal_hex_ip_private_valid_octal(self):
        """Lines 151-152: try block in _is_octal_hex_ip_private succeeds."""
        from src.urlps._security.ip_utils import _is_octal_hex_ip_private
        # 0177 = 127 in octal -> 127.0.0.1 is loopback
        result = _is_octal_hex_ip_private("0177.0.0.1")
        assert result is True

    def test_is_octal_hex_ip_private_hex(self):
        """_is_octal_hex_ip_private with hex octet."""
        from src.urlps._security.ip_utils import _is_octal_hex_ip_private
        # 0x7f = 127 hex -> 127.0.0.1 is loopback
        result = _is_octal_hex_ip_private("0x7f.0x0.0x0.0x1")
        assert result is True

    def test_check_resolved_ips_safe_invalid_ip(self):
        """Lines 169-170: ValueError on invalid sockaddr continues."""
        from src.urlps._security.ip_utils import _check_resolved_ips_safe
        # Simulate addr_info with an invalid IP string in sockaddr
        addr_info = [(2, 1, 6, "", ("invalid_ip_string", 80))]
        result = _check_resolved_ips_safe(addr_info)
        # Should continue and return True (no unsafe IP found)
        assert result is True

    def test_verify_connection_safe_empty_addr_info(self):
        """Line 177: _verify_connection_safe with empty list returns True."""
        from src.urlps._security.ip_utils import _verify_connection_safe
        result = _verify_connection_safe([], 1.0)
        assert result is True

    def test_is_private_ip_non_string(self):
        """Line 197: is_private_ip with non-string returns False."""
        from src.urlps._security import is_private_ip
        # Call the underlying function directly to bypass cache type-checking
        result = is_private_ip.__wrapped__(123)
        assert result is False

    def test_is_private_ip_non_string_none(self):
        """is_private_ip with None returns False."""
        from src.urlps._security import is_private_ip
        result = is_private_ip.__wrapped__(None)
        assert result is False
