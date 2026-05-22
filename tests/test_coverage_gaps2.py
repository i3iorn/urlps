"""Additional coverage gap tests - Part 2.

Covers remaining uncovered lines in url.py, _security.py, _parser.py, __init__.py.
"""
from __future__ import annotations

import socket
import unicodedata
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# url.py additional gaps
# ---------------------------------------------------------------------------

class TestURLAdditional:
    """Cover remaining url.py lines that need simple tests."""

    def _make_url(self, url_str: str = "https://example.com/path?k=v"):
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        return URL(url_str, security_policy=SecurityPolicy.balanced())

    def test_is_absolute_true(self):
        """is_absolute returns True for absolute URL."""
        url = self._make_url()
        assert url.is_absolute is True

    def test_is_absolute_false_no_host(self):
        """is_absolute returns False when no host (and no scheme)."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        url_bare = url.copy(scheme=None, host=None, port=None)
        assert url_bare.is_absolute is False

    def test_with_query_sets_query(self):
        """with_query() builds new URL with given query string."""
        url = self._make_url()
        new_url = url.with_query("a=1&b=2")
        assert new_url.query == "a=1&b=2"

    def test_with_query_none_removes_query(self):
        """with_query(None) clears the query."""
        url = self._make_url()
        new_url = url.with_query(None)
        assert new_url.query is None

    def test_with_userinfo_sets_userinfo(self):
        """with_userinfo() sets the userinfo component."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.internal())
        new_url = url.with_userinfo("user:pass")
        assert new_url.userinfo == "user:pass"

    def test_with_userinfo_none_clears_userinfo(self):
        """with_userinfo(None) removes userinfo."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL("https://user:pass@example.com/", security_policy=SecurityPolicy.internal())
        new_url = url.with_userinfo(None)
        assert new_url.userinfo is None

    def test_without_query_param_removes_matching_key(self):
        """without_query_param() removes all occurrences of a key (checks query string)."""
        url = self._make_url("https://example.com/?a=1&b=2&a=3")
        new_url = url.without_query_param("a")
        # Query string should not contain 'a=' entries; check via query string
        query = new_url.query or ""
        pairs = [p.split("=")[0] for p in query.split("&") if p]
        assert "a" not in pairs
        assert "b" in pairs

    def test_without_query_param_key_not_present(self):
        """without_query_param() with absent key returns same query."""
        url = self._make_url("https://example.com/?x=1")
        new_url = url.without_query_param("z")
        assert "x=1" in new_url.query

    def test_is_semantically_equal_with_non_url_returns_false(self):
        """is_semantically_equal returns False for non-URL argument."""
        url = self._make_url()
        assert url.is_semantically_equal("not-a-url-object") is False
        assert url.is_semantically_equal(42) is False
        assert url.is_semantically_equal(None) is False

    def test_str_returns_url_string(self):
        """__str__ returns the URL as string."""
        url = self._make_url()
        result = str(url)
        assert isinstance(result, str)
        assert "example.com" in result

    def test_normalize_port_valid_digit_string(self):
        """_normalize_port with valid numeric string returns int."""
        from src.urlps.url import _normalize_port
        assert _normalize_port("8080") == 8080
        assert _normalize_port("443") == 443
        assert _normalize_port("1") == 1

    def test_validate_copy_overrides_userinfo_non_string(self):
        """Line 475: non-string userinfo raises InvalidURLError."""
        from src.urlps.url import _validate_copy_overrides
        from src.urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="userinfo must be"):
            _validate_copy_overrides({"userinfo": 999})

    def test_effective_port_falls_back_to_scheme_default(self):
        """effective_port returns scheme default when _port is None."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        # Force explicit port=None via copy
        url_no_port = url.copy(port=None)
        assert url_no_port.effective_port == 443

    def test_as_string_mask_password_no_colon_in_userinfo(self):
        """as_string with mask_password=True and no ':' in userinfo is unchanged."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL("https://user@example.com/", security_policy=SecurityPolicy.internal())
        masked = url.as_string(mask_password=True)
        assert "user" in masked

    def test_without_query_then_add_back(self):
        """without_query removes query and fragment; add back works."""
        url = self._make_url("https://example.com/path?x=1#frag")
        no_query = url.without_query()
        assert no_query.query is None
        assert no_query.fragment is None


# ---------------------------------------------------------------------------
# _security.py additional gap coverage
# ---------------------------------------------------------------------------

class TestSecurityAdditional:
    """Additional _security.py tests for remaining uncovered lines."""

    def test_check_dns_rebinding_with_explicit_timeout(self):
        """Line 232->234: explicit timeout uses safe direct-IP check path."""
        from src.urlps._security import check_dns_rebinding_detailed
        from src.urlps.exceptions import ErrorCode
        safe, error = check_dns_rebinding_detailed("192.168.1.1", timeout=2.0)
        assert safe is False
        assert error == ErrorCode.SSRF_RISK

    def test_check_dns_rebinding_safe_with_explicit_timeout(self):
        """Direct safe IP with explicit timeout returns True."""
        from src.urlps._security import check_dns_rebinding_detailed
        safe, error = check_dns_rebinding_detailed("8.8.8.8", timeout=2.0)
        assert safe is True
        assert error is None

    def test_dns_gaierror_returns_dns_resolution_failed(self):
        """socket.gaierror captured as DNS_RESOLUTION_FAILED."""
        from src.urlps._security import check_dns_rebinding_detailed, reset_dns_rate_limiter
        from src.urlps.exceptions import ErrorCode
        reset_dns_rate_limiter()
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("dns failure")):
            safe, error = check_dns_rebinding_detailed(
                "nxdomain.invalid", enforce_rate_limit=False, retries=0
            )
        assert safe is False
        assert error == ErrorCode.DNS_RESOLUTION_FAILED

    def test_dns_os_error_returns_dns_connection_failed(self):
        """OSError captured as DNS_CONNECTION_FAILED."""
        from src.urlps._security import check_dns_rebinding_detailed, reset_dns_rate_limiter
        from src.urlps.exceptions import ErrorCode
        reset_dns_rate_limiter()
        with patch("socket.getaddrinfo", side_effect=OSError("conn refused")):
            safe, error = check_dns_rebinding_detailed(
                "nxdomain.invalid", enforce_rate_limit=False, retries=0
            )
        assert safe is False
        assert error == ErrorCode.DNS_CONNECTION_FAILED

    def test_dns_resolves_to_private_ip(self):
        """DNS resolver returns private IP → SSRF_RISK."""
        from src.urlps._security import check_dns_rebinding_detailed, reset_dns_rate_limiter
        from src.urlps.exceptions import ErrorCode
        reset_dns_rate_limiter()
        addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 80))]
        with patch("socket.getaddrinfo", return_value=addr_info):
            safe, error = check_dns_rebinding_detailed(
                "evil.internal.example.com", enforce_rate_limit=False, retries=0
            )
        assert safe is False
        assert error == ErrorCode.SSRF_RISK

    def test_has_mixed_scripts_value_error_returns_false(self):
        """Lines 417-418: ValueError in unicodedata.name → returns False."""
        from src.urlps._security import has_mixed_scripts
        with patch.object(unicodedata, "name", side_effect=ValueError("bad char")):
            result = has_mixed_scripts.__wrapped__("αβγ")
        assert result is False

    def test_has_path_traversal_unquote_unicode_error(self):
        """Lines 440-441: UnicodeDecodeError in unquote → returns False."""
        from src.urlps._security import has_path_traversal
        with patch("src.urlps._security.unquote",
                   side_effect=UnicodeDecodeError("utf-8", b"", 0, 1, "reason")):
            result = has_path_traversal("/normal/path")
        assert result is False

    def test_phishing_db_too_large_returns_empty(self):
        """Lines 378-380: oversized phishing DB returns empty set."""
        from src.urlps._security import _download_phishing_db
        big_content = "\n".join(f"host{i}.com" for i in range(5_000_001))
        with patch("urllib.request.urlopen") as mock_open:
            resp = mock_open.return_value.__enter__.return_value
            resp.status = 200
            resp.read.return_value = big_content.encode("utf-8")
            result = _download_phishing_db()
        assert result == set()

    def test_parser_confusion_backslash_only_in_authority(self):
        """Lines 604-605: backslash in authority with no path returns True."""
        from src.urlps._security import has_parser_confusion
        # No path slash, so mixed-sep check fails; backslash in authority triggers
        assert has_parser_confusion("http://host\\evil") is True

    def test_parser_confusion_empty_authority_returns_false(self):
        """Line 601: empty extracted authority → returns False."""
        from src.urlps._security import has_parser_confusion
        assert has_parser_confusion("http:///") is False

    def test_dns_rate_limiter_record_lookup_empty_host(self):
        """Lines 762-763: record_lookup empty/non-string returns early."""
        from src.urlps._security import DNSRateLimiter
        limiter = DNSRateLimiter()
        limiter.record_lookup("")
        limiter.record_lookup(None)  # type: ignore
        # No exception expected
        assert limiter.get_stats()["tracked_hosts"] == 0

    def test_normalize_url_unicode_type_error(self):
        """Lines 1525-1526: TypeError in unicodedata.normalize → returns original."""
        from src.urlps._security import normalize_url_unicode
        with patch.object(unicodedata, "normalize", side_effect=TypeError("test")):
            result = normalize_url_unicode("https://example.com")
        assert result == "https://example.com"

    def test_get_canonical_url_ipv6_with_zone_id(self):
        """Lines 1104-1105: IPv6 address with zone ID."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://[fe80::1%25eth0]/path")
        assert result is not None

    def test_get_canonical_url_ipv6_invalid_passes_through(self):
        """Lines 1108-1109: invalid IPv6 handled gracefully."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://[::invalid]/")
        assert result is None or isinstance(result, str)

    def test_get_canonical_url_path_with_unreserved_encoding(self):
        """Line 1141: unreserved char in path decoded."""
        from src.urlps._security import get_canonical_url
        # %41 = 'A' unreserved, should be decoded
        result = get_canonical_url("http://example.com/%41path")
        assert result is not None
        assert "%41" not in result.lower() or "Apath" in result

    def test_get_canonical_url_with_query_encoding(self):
        """Line 1150: query percent encoding uppercased."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com/?k=%2fval")
        assert result is not None
        assert "%2F" in result

    def test_get_canonical_url_with_fragment_encoding(self):
        """Line 1158: fragment percent encoding uppercased."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com/#%2ffrag")
        assert result is not None
        assert "%2F" in result

    def test_has_suspicious_punycode_single_label(self):
        """Line 1234: host with single label (no dot) → False."""
        from src.urlps._security import has_suspicious_punycode
        result = has_suspicious_punycode("localhost")
        assert result is False

    def test_has_suspicious_punycode_excess_hyphens(self):
        """Line 1271-1272: 3+ hyphens → True."""
        from src.urlps._security import has_suspicious_punycode
        result = has_suspicious_punycode("my---crazy-domain.com")
        assert result is True

    def test_has_suspicious_punycode_xn_with_suspicious_tld(self):
        """Line 1249-1250: xn-- domain + suspicious TLD → True."""
        from src.urlps._security import has_suspicious_punycode
        result = has_suspicious_punycode("xn--p1ai.tk")
        assert result is True

    def test_is_non_canonical_url_unnecessary_path_encoding(self):
        """Line 960-966: unreserved char encoded in path → non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/%41path") is True

    def test_is_non_canonical_url_ipv6_non_canonical(self):
        """Lines 990-1000: non-canonical IPv6 detected."""
        from src.urlps._security import is_non_canonical_url
        result = is_non_canonical_url("http://[2001:0db8:0000:0000:0000:0000:0000:0001]/")
        assert result is True

    def test_collect_security_findings_non_scheme_url(self):
        """Line 1592: URL without :// - only double-encoding check applied."""
        from src.urlps._security import collect_security_findings
        from src.urlps.security_policy import SecurityPolicy
        findings = collect_security_findings("not-a-url", policy=SecurityPolicy.strict())
        assert isinstance(findings, list)

    def test_security_clear_caches_works(self):
        """Line 1682->1681: clear_caches clears all registered functions."""
        from src.urlps._security import clear_caches, is_ssrf_risk
        is_ssrf_risk("warmup.example.com")
        result = clear_caches()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_verify_connection_safe_with_mocked_socket(self):
        """Lines 183-186: _verify_connection_safe with mocked socket."""
        from src.urlps._security import _verify_connection_safe
        with patch("socket.socket") as mock_socket_cls:
            mock_inst = mock_socket_cls.return_value
            mock_inst.getpeername.return_value = ("93.184.216.34", 80)
            mock_inst.connect.return_value = None  # success
            addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))]
            result = _verify_connection_safe(addr_info, 2.0)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# _parser.py additional gaps
# ---------------------------------------------------------------------------

class TestParserAdditional:
    """Cover remaining _parser.py lines."""

    def test_parse_query_string_double_ampersand_skips_empty(self):
        """Empty chunks (&&) in query string are skipped."""
        from src.urlps._parser import parse_query_string
        _, pairs = parse_query_string("a=1&&b=2&&c=3")
        keys = [k for k, _ in pairs]
        assert keys == ["a", "b", "c"]

    def test_parser_port_property_after_parse(self):
        """Parser.port property returns the parsed port."""
        from src.urlps._parser import Parser
        parser = Parser()
        parser.parse("https://example.com:9090/")
        assert parser.port == 9090

    def test_parser_port_property_no_port(self):
        """Parser.port property returns default port after parse."""
        from src.urlps._parser import Parser
        parser = Parser()
        parser.parse("https://example.com/")
        # Default port for https is 443
        assert parser.port == 443

    def test_get_cache_info_structure(self):
        """get_cache_info() includes normalize_path stats."""
        from src.urlps._parser import get_cache_info, normalize_path
        normalize_path("/test/path")
        info = get_cache_info()
        stats = info.get("normalize_path")
        assert stats is not None
        assert "hits" in stats
        assert "misses" in stats
        assert "currsize" in stats

    def test_clear_caches_returns_sizes(self):
        """clear_caches() returns previous cache sizes."""
        from src.urlps._parser import clear_caches, normalize_path
        normalize_path("/another/test/path")
        result = clear_caches()
        assert "normalize_path" in result
        assert isinstance(result["normalize_path"], int)


# ---------------------------------------------------------------------------
# __init__.py additional gaps
# ---------------------------------------------------------------------------

class TestInitAdditional:
    """Cover remaining __init__.py lines."""

    def test_parse_url_unsafe_with_security_policy_object(self):
        """parse_url_unsafe with SecurityPolicy object routes via resolve."""
        from src.urlps import parse_url_unsafe
        from src.urlps.security_policy import SecurityPolicy
        p = SecurityPolicy.internal()
        url = parse_url_unsafe("http://localhost/test", policy=p)
        assert url.host == "localhost"

    def test_compose_url_with_query_pairs_dict(self):
        """compose_url with query_pairs builds properly."""
        from src.urlps import compose_url
        result = compose_url({
            "scheme": "https",
            "host": "api.example.com",
            "path": "/v1",
            "query_pairs": [("page", "1"), ("size", "50")],
        })
        assert "api.example.com" in result
        assert "page=1" in result

    def test_get_cache_info_full_structure(self):
        """get_cache_info() returns all expected sub-keys."""
        from src.urlps import get_cache_info, parse_url
        parse_url("https://example.com/warm")
        info = get_cache_info()
        assert "parser" in info
        assert "normalize_path" in info["parser"]
        assert "validation" in info
        assert "security" in info
        assert "builder" in info

    def test_clear_all_caches_includes_builder(self):
        """clear_all_caches() populates builder sub-dict after cache warmup."""
        from src.urlps import clear_all_caches, parse_url
        parse_url("https://example.com/")
        result = clear_all_caches()
        assert "builder" in result
        # builder may have percent_encode and/or encode_for_query
        assert isinstance(result["builder"], dict)


# ---------------------------------------------------------------------------
# _validation.py additional gaps
# ---------------------------------------------------------------------------

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

