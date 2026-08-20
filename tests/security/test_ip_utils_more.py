"""Additional coverage for _security/ip_utils.py obfuscated-IP parsing edge cases."""

from __future__ import annotations

from urlps._security.ip_utils import (
    _is_obfuscated_ip_private,
    _parse_inet_aton_ipv4,
)


class TestParseInetAtonIpv4:
    def test_last_part_exceeding_remaining_bits_returns_none(self):
        # 1 leading octet (8 bits) leaves 24 bits for the last part;
        # 999999999 exceeds 2**24, so parsing must fail.
        assert _parse_inet_aton_ipv4("1.999999999") is None

    def test_single_value_exceeding_32_bits_returns_none(self):
        assert _parse_inet_aton_ipv4("99999999999") is None

    def test_valid_two_part_form_parses(self):
        address = _parse_inet_aton_ipv4("127.1")
        assert address is not None
        assert str(address) == "127.0.0.1"


class TestIsObfuscatedIpPrivate:
    def test_unparseable_host_is_not_flagged(self):
        assert _is_obfuscated_ip_private("not-an-ip") is False

    def test_private_two_part_form_is_flagged(self):
        assert _is_obfuscated_ip_private("127.1") is True
