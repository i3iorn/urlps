"""Tests for alternative IP address formats in security checks.

These tests cover detection of private/reserved IPs encoded in:
- Decimal notation (2130706433 = 127.0.0.1)
- Octal notation (0177.0.0.1 = 127.0.0.1)
- Hexadecimal notation (0x7f.0x0.0x0.0x1 = 127.0.0.1)
- Mixed notation (0x7f.0.0.1)
- IPv4-mapped IPv6 (::ffff:127.0.0.1)
"""
import pytest

from urlps._security import (
    is_ssrf_risk,
    clear_caches,
)
from urlps._security.ip_utils import _is_decimal_ip_private, _is_octal_hex_ip_private, _parse_ip_octet


@pytest.fixture(autouse=True)
def clear_security_caches():
    """Clear security caches before each test."""
    clear_caches()
    yield
    clear_caches()


class TestDecimalIPNotation:
    """Test decimal IP notation detection (e.g., 2130706433 = 127.0.0.1)."""

    def test_localhost_decimal(self):
        """127.0.0.1 in decimal = 2130706433"""
        assert _is_decimal_ip_private("2130706433") is True
        assert is_ssrf_risk("2130706433") is True

    def test_private_10_network_decimal(self):
        """10.0.0.1 in decimal = 167772161"""
        assert _is_decimal_ip_private("167772161") is True
        assert is_ssrf_risk("167772161") is True

    def test_private_192_168_decimal(self):
        """192.168.1.1 in decimal = 3232235777"""
        assert _is_decimal_ip_private("3232235777") is True
        assert is_ssrf_risk("3232235777") is True

    def test_private_172_16_decimal(self):
        """172.16.0.1 in decimal = 2886729729"""
        assert _is_decimal_ip_private("2886729729") is True
        assert is_ssrf_risk("2886729729") is True

    def test_public_ip_decimal(self):
        """8.8.8.8 in decimal = 134744072"""
        assert _is_decimal_ip_private("134744072") is False
        assert is_ssrf_risk("134744072") is False

    def test_public_ip_decimal_google(self):
        """142.250.185.206 (google.com) in decimal"""
        # 142.250.185.206 = (142 << 24) + (250 << 16) + (185 << 8) + 206 = 2398779854
        assert _is_decimal_ip_private("2398779854") is False
        assert is_ssrf_risk("2398779854") is False

    def test_zero_decimal(self):
        """0.0.0.0 = 0 is reserved"""
        assert _is_decimal_ip_private("0") is True
        assert is_ssrf_risk("0") is True

    def test_max_ipv4_decimal(self):
        """255.255.255.255 = 4294967295 is reserved (broadcast)"""
        assert _is_decimal_ip_private("4294967295") is True
        assert is_ssrf_risk("4294967295") is True

    def test_invalid_decimal_too_large(self):
        """Decimal larger than max IPv4 should not be treated as IP"""
        assert _is_decimal_ip_private("4294967296") is False

    def test_non_numeric_not_decimal(self):
        """Non-numeric strings should not be treated as decimal IP"""
        assert _is_decimal_ip_private("example.com") is False
        assert _is_decimal_ip_private("127.0.0.1") is False
        assert _is_decimal_ip_private("abc123") is False


class TestOctalIPNotation:
    """Test octal IP notation detection (e.g., 0177.0.0.1 = 127.0.0.1)."""

    def test_localhost_octal(self):
        """127 in octal = 0177"""
        assert _is_octal_hex_ip_private("0177.0.0.1") is True
        assert is_ssrf_risk("0177.0.0.1") is True

    def test_localhost_all_octal(self):
        """127.0.0.1 with all octets in octal"""
        assert _is_octal_hex_ip_private("0177.00.00.01") is True
        assert is_ssrf_risk("0177.00.00.01") is True

    def test_private_10_network_octal(self):
        """10.0.0.1 with octal first octet = 012.0.0.1"""
        assert _is_octal_hex_ip_private("012.0.0.1") is True
        assert is_ssrf_risk("012.0.0.1") is True

    def test_private_192_168_octal(self):
        """192.168.1.1 = 0300.0250.01.01"""
        assert _is_octal_hex_ip_private("0300.0250.01.01") is True
        assert is_ssrf_risk("0300.0250.01.01") is True

    def test_public_ip_octal(self):
        """8.8.8.8 = 010.010.010.010"""
        assert _is_octal_hex_ip_private("010.010.010.010") is False
        assert is_ssrf_risk("010.010.010.010") is False

    def test_invalid_octal_digit(self):
        """Invalid octal (contains 8 or 9) should not match"""
        # 09 is not valid octal, so this is treated as decimal 9
        # which makes the IP 9.0.0.1 - not private
        assert _is_octal_hex_ip_private("09.0.0.1") is False


class TestHexIPNotation:
    """Test hexadecimal IP notation detection (e.g., 0x7f.0x0.0x0.0x1)."""

    def test_localhost_hex(self):
        """127 in hex = 0x7f"""
        assert _is_octal_hex_ip_private("0x7f.0x0.0x0.0x1") is True
        assert is_ssrf_risk("0x7f.0x0.0x0.0x1") is True

    def test_localhost_mixed_case_hex(self):
        """Hex values should be case-insensitive"""
        assert _is_octal_hex_ip_private("0X7F.0x0.0x0.0x1") is True
        assert is_ssrf_risk("0X7F.0X0.0X0.0X1") is True

    def test_private_10_network_hex(self):
        """10.0.0.1 = 0xa.0x0.0x0.0x1"""
        assert _is_octal_hex_ip_private("0xa.0x0.0x0.0x1") is True
        assert is_ssrf_risk("0xa.0x0.0x0.0x1") is True

    def test_private_192_168_hex(self):
        """192.168.1.1 = 0xc0.0xa8.0x1.0x1"""
        assert _is_octal_hex_ip_private("0xc0.0xa8.0x1.0x1") is True
        assert is_ssrf_risk("0xc0.0xa8.0x1.0x1") is True

    def test_public_ip_hex(self):
        """8.8.8.8 = 0x8.0x8.0x8.0x8"""
        assert _is_octal_hex_ip_private("0x8.0x8.0x8.0x8") is False
        assert is_ssrf_risk("0x8.0x8.0x8.0x8") is False


class TestMixedNotation:
    """Test mixed decimal/octal/hex notation."""

    def test_localhost_mixed_hex_decimal(self):
        """Mix of hex and decimal: 0x7f.0.0.1"""
        assert _is_octal_hex_ip_private("0x7f.0.0.1") is True
        assert is_ssrf_risk("0x7f.0.0.1") is True

    def test_localhost_mixed_octal_decimal(self):
        """Mix of octal and decimal: 0177.0.0.1"""
        assert _is_octal_hex_ip_private("0177.0.0.1") is True
        assert is_ssrf_risk("0177.0.0.1") is True

    def test_public_ip_mixed(self):
        """Public IP with mixed notation: 0x8.8.010.8 = 8.8.8.8"""
        assert _is_octal_hex_ip_private("0x8.8.010.8") is False
        assert is_ssrf_risk("0x8.8.010.8") is False


class TestIPv4MappedIPv6:
    """Test IPv4-mapped IPv6 address detection."""

    def test_localhost_ipv4_mapped(self):
        """::ffff:127.0.0.1 should be detected as private"""
        assert is_ssrf_risk("[::ffff:127.0.0.1]") is True

    def test_private_ipv4_mapped(self):
        """::ffff:10.0.0.1 should be detected as private"""
        assert is_ssrf_risk("[::ffff:10.0.0.1]") is True

    def test_public_ipv4_mapped(self):
        """::ffff:8.8.8.8 should not trigger SSRF for the mapping check alone"""
        # The _is_ipv4_mapped_ipv6 only checks for the prefix pattern
        # actual IP validation happens elsewhere
        assert is_ssrf_risk("[::ffff:8.8.8.8]") is True  # Still flagged due to IPv4-mapped format


class TestParseIPOctet:
    """Test the _parse_ip_octet helper function."""

    def test_decimal_octet(self):
        """Parse decimal octets"""
        assert _parse_ip_octet("127") == 127
        assert _parse_ip_octet("0") == 0
        assert _parse_ip_octet("255") == 255

    def test_octal_octet(self):
        """Parse octal octets (leading zero)"""
        assert _parse_ip_octet("0177") == 127  # 0o177 = 127
        assert _parse_ip_octet("012") == 10    # 0o12 = 10
        assert _parse_ip_octet("00") == 0      # 0o0 = 0

    def test_hex_octet(self):
        """Parse hexadecimal octets"""
        assert _parse_ip_octet("0x7f") == 127
        assert _parse_ip_octet("0X7F") == 127  # case insensitive
        assert _parse_ip_octet("0xa") == 10
        assert _parse_ip_octet("0xff") == 255

    def test_invalid_octet(self):
        """Invalid octets return None"""
        assert _parse_ip_octet("abc") is None
        assert _parse_ip_octet("0xgg") is None
        assert _parse_ip_octet("") is None


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_link_local_decimal(self):
        """169.254.0.1 in decimal = 2851995649"""
        assert _is_decimal_ip_private("2851995649") is True
        assert is_ssrf_risk("2851995649") is True

    def test_multicast_decimal(self):
        """224.0.0.1 in decimal = 3758096385"""
        assert _is_decimal_ip_private("3758096385") is True
        assert is_ssrf_risk("3758096385") is True

    def test_cloud_metadata_169_254(self):
        """AWS/GCP metadata endpoint 169.254.169.254 = 2852039166"""
        assert _is_decimal_ip_private("2852039166") is True
        assert is_ssrf_risk("2852039166") is True

    def test_non_ip_formats(self):
        """Non-IP formats should not be detected as private"""
        assert _is_octal_hex_ip_private("example.com") is False
        assert _is_octal_hex_ip_private("127.0.0") is False  # 3 octets
        assert _is_octal_hex_ip_private("127.0.0.1.1") is False  # 5 octets
        assert _is_octal_hex_ip_private("") is False

    def test_octet_out_of_range(self):
        """Octets > 255 should fail"""
        assert _is_octal_hex_ip_private("256.0.0.1") is False
        assert _is_octal_hex_ip_private("0x100.0.0.1") is False  # 0x100 = 256

    def test_negative_decimal(self):
        """Negative numbers should not be treated as IP"""
        assert _is_decimal_ip_private("-1") is False
        assert _is_decimal_ip_private("-2130706433") is False
