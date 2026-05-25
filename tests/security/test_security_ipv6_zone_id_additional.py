"""Additional IPv6 zone ID and parser-confusion security tests."""

from __future__ import annotations

class TestSecurityIPv6ZoneId:
    def test_malicious_ipv6_zone_id_empty_zone(self):
        """Lines 476-477: empty zone ID is malicious."""
        from src.urlps._security import is_malicious_ipv6_zone_id
        result = is_malicious_ipv6_zone_id("[::1%25]")
        assert result is True

    def test_malicious_ipv6_zone_id_invalid_zone_chars(self):
        """Lines 476-477: invalid chars in zone ID returns True."""
        from src.urlps._security import is_malicious_ipv6_zone_id
        result = is_malicious_ipv6_zone_id("[fe80::1%25<script>]")
        assert result is True

    def test_malicious_ipv6_zone_id_valid_zone(self):
        """is_malicious_ipv6_zone_id returns False for valid zone char."""
        from src.urlps._security import is_malicious_ipv6_zone_id
        result = is_malicious_ipv6_zone_id("[fe80::1%25eth0]")
        assert result is False

    def test_parser_confusion_backslash_in_authority(self):
        """Line 612: backslash in authority returns True."""
        from src.urlps._security import has_parser_confusion
        result = has_parser_confusion("http://example.com\\evil.com/path")
        assert result is True

    def test_parser_confusion_empty_authority(self):
        """Line 605: empty authority returns False."""
        from src.urlps._security import has_parser_confusion
        # URL with scheme and no authority portion
        result = has_parser_confusion("http:///")
        assert result is False
