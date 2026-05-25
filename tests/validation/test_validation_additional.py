"""Additional validation tests grouped by validator behavior."""

from __future__ import annotations

class TestValidation:
    def test_to_ascii_host_with_idna_module(self):
        """Line 77: _to_ascii_host using idna module path."""
        from src.urlps._validation import Validator
        # This tests IDNA encoding of a punycode-capable host
        result = Validator._to_ascii_host.__wrapped__("münchen.de")
        assert isinstance(result, str)

    def test_is_valid_host_too_long_after_ascii(self):
        """Line 110: ASCII host exceeds MAX_HOST_LENGTH."""
        from src.urlps._validation import Validator
        from src.urlps.constants import MAX_HOST_LENGTH
        # Build a host that is short in unicode but long in ASCII
        # This requires a label that when IDNA-encoded exceeds max length
        long_host = "a" * (MAX_HOST_LENGTH + 1) + ".com"
        result = Validator.is_valid_host.__wrapped__(long_host)
        assert result is False

    def test_validate_ipv4_octets_leading_zero(self):
        """Line 140: octet with leading zero returns False."""
        from src.urlps._validation import Validator
        result = Validator._validate_ipv4_octets("192.168.01.1")
        assert result is False

    def test_validate_ipv4_octets_invalid_value(self):
        """Lines 147-148: ValueError in int() returns False."""
        from src.urlps._validation import Validator
        # An octet that isn't parseable as int
        result = Validator._validate_ipv4_octets("192.168.1.abc")
        assert result is False

    def test_is_standard_port_type_error(self):
        """Lines 211-212: TypeError returns False in is_standard_port."""
        from src.urlps._validation import Validator
        result = Validator.is_standard_port("not_a_port_int")
        assert result is False

    def test_is_url_safe_string_non_string(self):
        """Line 228: non-string returns False in is_url_safe_string."""
        from src.urlps._validation import Validator
        result = Validator.is_url_safe_string.__wrapped__(123)
        assert result is False

    def test_is_url_safe_string_none(self):
        """is_url_safe_string with None returns False."""
        from src.urlps._validation import Validator
        result = Validator.is_url_safe_string.__wrapped__(None)
        assert result is False

    def test_is_ip_address_non_string(self):
        """Line 282: is_ip_address with non-string returns False."""
        from src.urlps._validation import Validator
        result = Validator.is_ip_address.__wrapped__(123)
        assert result is False

    def test_get_cache_info_none_for_non_cached(self):
        """Line 302: get_cache_info returns None for methods without cache_info."""
        from src.urlps._validation import Validator
        # Temporarily inject a non-cached method name
        original = Validator._CACHED_METHODS[:]
        Validator._CACHED_METHODS = ["_validate_ipv4_octets"]  # not LRU cached
        try:
            info = Validator.get_cache_info()
            assert info.get("_validate_ipv4_octets") is None
        finally:
            Validator._CACHED_METHODS = original

    def test_clear_caches_zero_for_non_cached_method(self):
        """Lines 317->313, 320: clear_caches returns 0 for non-cached methods."""
        from src.urlps._validation import Validator
        original = Validator._CACHED_METHODS[:]
        Validator._CACHED_METHODS = ["_validate_ipv4_octets"]  # not LRU cached
        try:
            result = Validator.clear_caches()
            assert result.get("_validate_ipv4_octets") == 0
        finally:
            Validator._CACHED_METHODS = original

class TestValidationAdditional:
    """Additional validation tests for remaining lines."""

    def test_is_valid_host_non_ascii_too_long_after_encode(self):
        """Line 110: host short in Unicode but long ASCII representation."""
        from src.urlps._validation import Validator
        from src.urlps.constants import MAX_HOST_LENGTH
        # Build a host that exceeds MAX_HOST_LENGTH after IDNA encoding
        very_long = "a" * 64 + "." + "b" * 64 + "." + "c" * 64 + "." + "d" * 64 + ".com"
        result = Validator.is_valid_host.__wrapped__(very_long)
        assert result is False

    def test_validate_ipv4_octets_no_leading_zero_ok(self):
        """Valid octets without leading zeros pass."""
        from src.urlps._validation import Validator
        assert Validator._validate_ipv4_octets("192.168.1.1") is True

    def test_clear_caches_with_non_cached_method_name(self):
        """Line 317->313, 320: clear_caches handles non-LRU methods correctly."""
        from src.urlps._validation import Validator
        original = Validator._CACHED_METHODS[:]
        Validator._CACHED_METHODS = ["_validate_ipv4_octets", "is_valid_port"]
        try:
            result = Validator.clear_caches()
            # _validate_ipv4_octets has no LRU, is_valid_port has no LRU either
            assert result.get("_validate_ipv4_octets") == 0
        finally:
            Validator._CACHED_METHODS = original
