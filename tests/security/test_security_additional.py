"""Additional security behavior tests grouped by helper coverage."""

from __future__ import annotations

import socket
import unicodedata
from unittest.mock import patch
import pytest

class TestSecurityAdditional:
    """Additional _security.py tests for remaining uncovered lines."""

    def test_check_dns_rebinding_with_explicit_timeout(self):
        """Line 232->234: explicit timeout uses safe direct-IP check path."""
        from src.urlps._security import check_dns_rebinding_detailed
        from src.urlps.exceptions import ErrorCode
        safe, error = check_dns_rebinding_detailed("192.168.1.1", timeout_seconds=2.0)
        assert safe is False
        assert error == ErrorCode.SSRF_RISK

    def test_check_dns_rebinding_safe_with_explicit_timeout(self):
        """Direct safe IP with explicit timeout returns True."""
        from src.urlps._security import check_dns_rebinding_detailed
        safe, error = check_dns_rebinding_detailed("8.8.8.8", timeout_seconds=2.0)
        assert safe is True
        assert error is None

    def test_has_mixed_scripts_value_error_returns_false(self):
        """Lines 417-418: ValueError in unicodedata.name → returns False."""
        from src.urlps._security import has_mixed_scripts
        with patch.object(unicodedata, "name", side_effect=ValueError("bad char")):
            result = has_mixed_scripts.__wrapped__("αβγ")
        assert result is False

    def test_has_path_traversal_unquote_unicode_error(self):
        """Lines 440-441: UnicodeDecodeError in unquote → returns False."""
        from src.urlps._security import has_path_traversal
        with patch("src.urlps._security.url_checks.unquote",
                   side_effect=UnicodeDecodeError("utf-8", b"", 0, 1, "reason")):
            result = has_path_traversal("/normal/path")
        assert result is False

    def test_phishing_db_too_large_returns_empty(self):
        """Oversized phishing DB downloads fail closed with an empty database."""
        from src.urlps._security.phishing_db import refresh_phishing_db, get_phishing_db_info
        from src.urlps.constants import DEFAULT_PHISHING_DATABASE_MAX_BYTES

        oversized_bytes = b"a" * (DEFAULT_PHISHING_DATABASE_MAX_BYTES + 1)
        with patch("urllib.request.urlopen") as mock_open:
            resp = mock_open.return_value.__enter__.return_value
            resp.status = 200
            resp.read.return_value = oversized_bytes

            count = refresh_phishing_db()
            info = get_phishing_db_info()

        assert count == 0
        assert info["size"] == 0
        assert info["last_error"] == "download_too_large"

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
        assert limiter.stats()["tracked_hosts"] == 0

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
        from src.urlps._security.policy import SecurityPolicy
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
        from src.urlps._security.ip_utils import _verify_connection_safe
        with patch("socket.socket") as mock_socket_cls:
            mock_inst = mock_socket_cls.return_value
            mock_inst.getpeername.return_value = ("93.184.216.34", 80)
            mock_inst.connect.return_value = None  # success
            addr_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))]
            result = _verify_connection_safe(addr_info, 2.0)
        assert isinstance(result, bool)
