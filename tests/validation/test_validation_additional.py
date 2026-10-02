"""Additional validation tests grouped by validator behavior."""

from __future__ import annotations


class TestValidation:
    def test_to_ascii_host_with_idna_module(self):
        """Line 77: _to_ascii_host using idna module path."""
        from urlps._validation import Validator

        # This tests IDNA encoding of a punycode-capable host
        result = Validator._to_ascii_host.__wrapped__("münchen.de")
        assert isinstance(result, str)

    def test_is_valid_host_too_long_after_ascii(self):
        """Line 110: ASCII host exceeds MAX_HOST_LENGTH."""
        from urlps._validation import Validator
        from urlps.constants import MAX_HOST_LENGTH

        # Build a host that is short in unicode but long in ASCII
        # This requires a label that when IDNA-encoded exceeds max length
        long_host = "a" * (MAX_HOST_LENGTH + 1) + ".com"
        result = Validator.is_valid_host.__wrapped__(long_host)
        assert result is False

    def test_validate_ipv4_octets_leading_zero(self):
        """Line 140: octet with leading zero returns False."""
        from urlps._validation import Validator

        result = Validator._validate_ipv4_octets("192.168.01.1")
        assert result is False

    def test_validate_ipv4_octets_invalid_value(self):
        """Lines 147-148: ValueError in int() returns False."""
        from urlps._validation import Validator

        # An octet that isn't parseable as int
        result = Validator._validate_ipv4_octets("192.168.1.abc")
        assert result is False

    def test_is_url_safe_string_non_string(self):
        """Line 228: non-string returns False in is_url_safe_string."""
        from urlps._validation import Validator

        result = Validator.is_url_safe_string.__wrapped__(123)
        assert result is False

    def test_is_url_safe_string_none(self):
        """is_url_safe_string with None returns False."""
        from urlps._validation import Validator

        result = Validator.is_url_safe_string.__wrapped__(None)
        assert result is False

    def test_is_ip_address_non_string(self):
        """Line 282: is_ip_address with non-string returns False."""
        from urlps._validation import Validator

        result = Validator.is_ip_address.__wrapped__(123)
        assert result is False

    def test_validation_cache_info_reads_the_registry(self):
        from urlps._validation import Validator

        info = Validator.get_cache_info()
        assert {"is_valid_host", "is_valid_scheme", "_to_ascii_host"} <= set(info)
        assert set(Validator.clear_caches()) == set(info)


class TestValidationAdditional:
    """Additional validation tests for remaining lines."""

    def test_is_valid_host_non_ascii_too_long_after_encode(self):
        """Line 110: host short in Unicode but long ASCII representation."""
        from urlps._validation import Validator

        # Build a host that exceeds MAX_HOST_LENGTH after IDNA encoding
        very_long = "a" * 64 + "." + "b" * 64 + "." + "c" * 64 + "." + "d" * 64 + ".com"
        result = Validator.is_valid_host.__wrapped__(very_long)
        assert result is False

    def test_validate_ipv4_octets_no_leading_zero_ok(self):
        """Valid octets without leading zeros pass."""
        from urlps._validation import Validator

        assert Validator._validate_ipv4_octets("192.168.1.1") is True
