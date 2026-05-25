"""Security fuzzing tests for urlp (improvement #10).

These tests use property-based testing to find edge cases that could crash
or exploit the URL parser. Install hypothesis for these tests:
    pip install hypothesis

Run with:
    pytest tests/test_security_fuzzing.py -v
"""
import pytest

try:
    from hypothesis import given, strategies as st, settings, assume
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False
    # Create no-op decorators for when hypothesis is not installed
    def given(*args, **kwargs):
        def decorator(func):
            return pytest.mark.skip(reason="hypothesis not installed")(func)
        return decorator

    def settings(*args, **kwargs):
        def decorator(func):
            return func
        return decorator

    class st:
        @staticmethod
        def text(*args, **kwargs):
            return None
        @staticmethod
        def characters(*args, **kwargs):
            return None
        @staticmethod
        def integers(*args, **kwargs):
            return None

    def assume(condition):
        pass

from urlps import parse_url, parse_url_unsafe, URLParseError, InvalidURLError
from urlps._validation import Validator as ValidatorClass, is_valid_userinfo
from urlps import _security


class TestParserFuzzing:
    """Fuzz testing for the URL parser."""

    @given(st.text(max_size=10000))
    @settings(max_examples=500)
    def test_parser_handles_arbitrary_input(self, url_input):
        """Ensure parser never crashes on arbitrary input."""
        try:
            parse_url_unsafe(url_input)
        except (URLParseError, InvalidURLError, ValueError, TypeError):
            pass  # Expected for invalid input
        # No other exceptions should occur - test passes if we get here

    @given(st.text(max_size=1000))
    @settings(max_examples=300)
    def test_parser_with_scheme_prefix(self, url_input):
        """Test parser with various scheme prefixes."""
        for scheme in ['http://', 'https://', 'ftp://', 'file://', 'ws://']:
            try:
                parse_url_unsafe(scheme + url_input)
            except (URLParseError, InvalidURLError, ValueError, TypeError):
                pass  # Expected for invalid input

    @given(st.text(alphabet='abcdefghijklmnopqrstuvwxyz0123456789.-', min_size=1, max_size=500))
    @settings(max_examples=300)
    def test_host_validation_completes(self, host_input):
        """Ensure host validation completes in reasonable time (ReDoS protection)."""
        # This should never hang due to catastrophic backtracking
        ValidatorClass.is_valid_host(host_input)

    @given(st.text(alphabet='0123456789.', min_size=1, max_size=50))
    @settings(max_examples=200)
    def test_ipv4_validation_completes(self, ip_input):
        """Ensure IPv4 validation completes quickly."""
        ValidatorClass.is_valid_ipv4(ip_input)

    @given(st.text(alphabet='0123456789abcdefABCDEF:[]%', min_size=1, max_size=100))
    @settings(max_examples=200)
    def test_ipv6_validation_completes(self, ip_input):
        """Ensure IPv6 validation completes quickly."""
        ValidatorClass.is_valid_ipv6(ip_input)

    @given(st.text(alphabet='abcdefghijklmnopqrstuvwxyz0123456789:@', min_size=1, max_size=500))
    @settings(max_examples=300)
    def test_userinfo_validation_completes(self, userinfo_input):
        """Ensure userinfo validation completes in reasonable time (ReDoS protection).

        The old regex r"^[^:@]+(?::[^@]*)?$" was vulnerable to catastrophic
        backtracking on inputs like "a:" + "b" * 100000 + "@".
        """
        # This should complete quickly without hanging
        result = is_valid_userinfo(userinfo_input)
        assert isinstance(result, bool)


class TestReDoSProtection:
    """Specific tests for ReDoS vulnerability protection."""

    def test_userinfo_redos_attack_string(self):
        """Test the specific attack string that caused ReDoS in the old regex.

        The pattern "a:" + "b" * N + "@" would cause catastrophic backtracking
        in the old regex r"^[^:@]+(?::[^@]*)?$".
        """
        import time

        # This attack string would hang the old regex implementation
        attack_string = "a:" + "b" * 100000 + "@"

        start = time.perf_counter()
        result = is_valid_userinfo(attack_string)
        elapsed = time.perf_counter() - start

        # Should complete in well under 1 second (old regex would hang)
        assert elapsed < 1.0, f"Validation took too long: {elapsed:.2f}s"
        # Should return False because @ is not allowed
        assert result is False

    def test_userinfo_redos_without_at(self):
        """Test long userinfo strings without @ character."""
        import time

        # Long password after colon
        long_password = "user:" + "x" * 100000

        start = time.perf_counter()
        result = is_valid_userinfo(long_password)
        elapsed = time.perf_counter() - start

        # Should complete quickly
        assert elapsed < 1.0, f"Validation took too long: {elapsed:.2f}s"
        # Should return False because it exceeds max length
        assert result is False

    def test_userinfo_valid_cases(self):
        """Ensure valid userinfo cases still work correctly."""
        assert is_valid_userinfo("user") is True
        assert is_valid_userinfo("user:pass") is True
        assert is_valid_userinfo("user:") is True  # Empty password is valid
        assert is_valid_userinfo("user:pass:word") is True  # Multiple colons in password
        assert is_valid_userinfo("a:b") is True

    def test_userinfo_invalid_cases(self):
        """Ensure invalid userinfo cases are rejected."""
        assert is_valid_userinfo("") is False  # Empty
        assert is_valid_userinfo(":pass") is False  # Empty username
        assert is_valid_userinfo("user@host") is False  # Contains @
        assert is_valid_userinfo("user:pass@") is False  # Contains @
        assert is_valid_userinfo("@") is False  # Just @


class TestValidatorFuzzing:
    """Fuzz testing for the Validator class."""

    @given(st.text(max_size=500))
    @settings(max_examples=300)
    def test_scheme_validation_safe(self, scheme):
        """Ensure scheme validation handles any input."""
        result = ValidatorClass.is_valid_scheme(scheme)
        assert isinstance(result, bool)

    @given(st.text(max_size=500))
    @settings(max_examples=300)
    def test_fragment_validation_safe(self, fragment):
        """Ensure fragment validation handles any input."""
        result = ValidatorClass.is_valid_fragment(fragment)
        assert isinstance(result, bool)

    @given(st.text(max_size=500))
    @settings(max_examples=300)
    def test_url_safe_string_validation(self, text):
        """Ensure URL safe string validation handles any input."""
        result = ValidatorClass.is_url_safe_string(text)
        assert isinstance(result, bool)

    @given(st.text(max_size=200))
    @settings(max_examples=200)
    def test_ssrf_risk_detection(self, host):
        """Ensure SSRF risk detection handles any input."""
        result = _security.is_ssrf_risk(host)
        assert isinstance(result, bool)

    @given(st.text(max_size=200))
    @settings(max_examples=200)
    def test_mixed_scripts_detection(self, host):
        """Ensure mixed scripts detection handles any input."""
        result = _security.has_mixed_scripts(host)
        assert isinstance(result, bool)


class TestEdgeCases:
    """Specific edge case tests for security."""

    def test_null_byte_rejection(self):
        """Ensure null bytes are rejected."""
        with pytest.raises((URLParseError, InvalidURLError)):
            parse_url("http://example.com/\x00path")

    def test_control_character_rejection(self):
        """Ensure control characters are rejected."""
        with pytest.raises((URLParseError, InvalidURLError)):
            parse_url("http://example.com/\x01path")

    def test_very_long_scheme_rejected(self):
        """Ensure very long schemes are rejected."""
        long_scheme = "a" * 100
        with pytest.raises(URLParseError):
            parse_url(f"{long_scheme}://example.com")

    def test_very_long_host_rejected(self):
        """Ensure very long hosts are rejected."""
        long_host = "a" * 300 + ".com"
        with pytest.raises((URLParseError, InvalidURLError)):
            parse_url(f"http://{long_host}/")

    def test_very_long_path_rejected(self):
        """Ensure very long paths are rejected."""
        long_path = "/a" * 5000
        with pytest.raises(URLParseError):
            parse_url(f"http://example.com{long_path}")

    def test_very_long_query_rejected(self):
        """Ensure very long queries are rejected."""
        long_query = "a=b&" * 20000
        with pytest.raises((URLParseError, InvalidURLError)):
            parse_url(f"http://example.com?{long_query}")

    def test_ssrf_localhost_blocked_strict(self):
        """Ensure localhost is blocked in strict mode (now default)."""
        with pytest.raises(InvalidURLError):
            parse_url("http://localhost/")

    def test_ssrf_private_ip_blocked_strict(self):
        """Ensure private IPs are blocked in strict mode (now default)."""
        with pytest.raises(InvalidURLError):
            parse_url("http://192.168.1.1/")

    def test_ssrf_loopback_blocked_strict(self):
        """Ensure loopback IPs are blocked in strict mode (now default)."""
        with pytest.raises(InvalidURLError):
            parse_url("http://127.0.0.1/")

    def test_ssrf_ipv6_loopback_blocked_strict(self):
        """Ensure IPv6 loopback is blocked in strict mode (now default)."""
        with pytest.raises(InvalidURLError):
            parse_url("http://[::1]/")

    def test_ssrf_local_domain_blocked_strict(self):
        """Ensure .local domains are blocked in strict mode (now default)."""
        with pytest.raises(InvalidURLError):
            parse_url("http://printer.local/")

    def test_ssrf_ipv4_mapped_ipv6_blocked_strict(self):
        """Ensure IPv4-mapped IPv6 addresses are blocked in strict mode (now default)."""
        with pytest.raises(InvalidURLError):
            parse_url("http://[::ffff:127.0.0.1]/")

    def test_exception_doesnt_leak_input_without_debug(self):
        """Ensure exceptions don't leak input when debug=False."""
        try:
            parse_url_unsafe("http://invalid\x00host/", debug=False)
        except URLParseError as e:
            # Exception message should not contain the raw input
            assert "\x00" not in str(e)

    def test_frozen_url_hashable(self):
        """Ensure frozen URLs can be hashed."""
        url = parse_url("http://example.com/path")
        hash_value = hash(url)
        assert isinstance(hash_value, int)

    def test_url_always_hashable(self):
        """URLs are now always immutable and hashable."""
        url = parse_url("http://example.com/path")
        # URLs are always immutable now, so they should be hashable
        hash_value = hash(url)
        assert isinstance(hash_value, int)

    def test_url_equality(self):
        """Test URL equality comparison."""
        url1 = parse_url("http://example.com/path")
        url2 = parse_url("http://example.com/path")
        url3 = parse_url("http://example.com/other")

        assert url1 == url2
        assert url1 != url3

    def test_frozen_urls_in_set(self):
        """Ensure frozen URLs can be used in sets."""
        url1 = parse_url("http://example.com/path")
        url2 = parse_url("http://example.com/path")
        url3 = parse_url("http://example.com/other")

        url_set = {url1, url2, url3}
        assert len(url_set) == 2  # url1 and url2 are equal

    def test_same_origin_comparison(self):
        """Test same-origin comparisons."""
        url1 = parse_url("http://example.com/path1")
        url2 = parse_url("http://example.com/path2")
        url3 = parse_url("https://example.com/path1")
        url4 = parse_url("http://other.com/path1")

        assert url1.same_origin(url2)  # Same origin, different paths
        assert not url1.same_origin(url3)  # Different scheme
        assert not url1.same_origin(url4)  # Different host

    def test_origin_property(self):
        """Test origin property."""
        url = parse_url("http://example.com:8080/path?query=value#fragment")
        assert url.origin == "http://example.com:8080"

        # Default port should be omitted
        url2 = parse_url("http://example.com/path")
        assert url2.origin == "http://example.com"

    def test_type_validation_url_not_string(self):
        """Ensure TypeError is raised for non-string URL."""
        with pytest.raises(TypeError, match="must be str"):
            parse_url_unsafe(12345)  # type: ignore

    def test_type_validation_strict_not_bool(self):
        """Ensure TypeError is raised for non-bool strict in parse_url_unsafe."""
        with pytest.raises(TypeError, match="must be bool"):
            parse_url_unsafe("http://example.com", strict="yes")  # type: ignore


class TestHomographDetection:
    """Tests for homograph attack detection."""

    def test_pure_latin_not_mixed(self):
        """Pure Latin text should not be flagged."""
        assert not _security.has_mixed_scripts("example")

    def test_pure_cyrillic_not_mixed(self):
        """Pure Cyrillic text should not be flagged."""
        assert not _security.has_mixed_scripts("примір")

    def test_mixed_latin_cyrillic_flagged(self):
        """Mixed Latin and Cyrillic should be flagged."""
        # 'а' is Cyrillic, rest is Latin
        assert _security.has_mixed_scripts("exаmple")  # Cyrillic 'а'

    def test_numbers_and_dots_ignored(self):
        """Numbers and dots should not trigger mixed scripts."""
        assert not _security.has_mixed_scripts("example.com")
        assert not _security.has_mixed_scripts("example123.com")


class TestSSRFProtection:
    """Tests for SSRF protection."""

    def test_localhost_is_ssrf_risk(self):
        """localhost should be flagged as SSRF risk."""
        assert _security.is_ssrf_risk("localhost")

    def test_127_0_0_1_is_ssrf_risk(self):
        """127.0.0.1 should be flagged as SSRF risk."""
        assert _security.is_ssrf_risk("127.0.0.1")

    def test_private_ip_is_ssrf_risk(self):
        """Private IPs should be flagged as SSRF risk."""
        assert _security.is_ssrf_risk("192.168.1.1")
        assert _security.is_ssrf_risk("10.0.0.1")
        assert _security.is_ssrf_risk("172.16.0.1")

    def test_public_ip_not_ssrf_risk(self):
        """Public IPs should not be flagged as SSRF risk."""
        assert not _security.is_ssrf_risk("8.8.8.8")
        assert not _security.is_ssrf_risk("1.1.1.1")

    def test_local_domain_is_ssrf_risk(self):
        """.local domains should be flagged as SSRF risk."""
        assert _security.is_ssrf_risk("printer.local")
        assert _security.is_ssrf_risk("mydevice.localhost")

    def test_public_domain_not_ssrf_risk(self):
        """Public domains should not be flagged as SSRF risk."""
        assert not _security.is_ssrf_risk("example.com")
        assert not _security.is_ssrf_risk("google.com")

    def test_ipv6_loopback_is_ssrf_risk(self):
        """IPv6 loopback should be flagged as SSRF risk."""
        assert _security.is_ssrf_risk("[::1]")

    def test_ipv4_mapped_ipv6_is_ssrf_risk(self):
        """IPv4-mapped IPv6 addresses should be flagged as SSRF risk."""
        assert _security.is_ssrf_risk("[::ffff:127.0.0.1]")
        assert _security.is_ssrf_risk("[::FFFF:192.168.1.1]")
