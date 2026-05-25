"""Additional URL-level security helper tests."""

from __future__ import annotations

class TestSecurityMixedScripts:
    def test_has_mixed_scripts_non_string(self):
        """Line 397: has_mixed_scripts with non-string returns False."""
        from urlps._security import has_mixed_scripts
        result = has_mixed_scripts.__wrapped__(123)
        assert result is False

    def test_has_mixed_scripts_none(self):
        """has_mixed_scripts with None returns False."""
        from urlps._security import has_mixed_scripts
        result = has_mixed_scripts.__wrapped__(None)
        assert result is False

    def test_has_double_encoding_non_string(self):
        """Line 424: has_double_encoding with non-string returns False."""
        from urlps._security import has_double_encoding
        result = has_double_encoding(123)
        assert result is False

    def test_has_double_encoding_none(self):
        """has_double_encoding with None returns False."""
        from urlps._security import has_double_encoding
        result = has_double_encoding(None)
        assert result is False

    def test_has_path_traversal_non_string(self):
        """Line 431: has_path_traversal with non-string returns False."""
        from urlps._security import has_path_traversal
        result = has_path_traversal(123)
        assert result is False

    def test_has_path_traversal_double_encoded(self):
        """Lines 439: has_path_traversal detects double-encoded traversal."""
        from urlps._security import has_path_traversal
        # %252e%252e → %2e%2e → .. (double encoded)
        result = has_path_traversal("%252e%252e")
        assert result is True

    def test_has_path_traversal_returns_false_for_safe_path(self):
        """Line 448: has_path_traversal returns False for safe paths."""
        from urlps._security import has_path_traversal
        result = has_path_traversal("/safe/path/here")
        assert result is False

    def test_is_open_redirect_risk_non_string(self):
        """is_open_redirect_risk with non-string returns False."""
        from urlps._security import is_open_redirect_risk
        result = is_open_redirect_risk(123)
        assert result is False

class TestSecurityExtractHostPath:
    def test_extract_host_and_path_no_scheme(self):
        """Line 1482: URL without :// returns empty strings."""
        from urlps._security import extract_host_and_path
        host, path = extract_host_and_path("example.com/path")
        assert host == ""
        assert path == ""

class TestSecurityMiscellaneous:
    def test_normalize_url_unicode_non_string(self):
        """Lines 1525-1526: non-string input returned unchanged."""
        from urlps._security import normalize_url_unicode
        result = normalize_url_unicode(123)
        assert result == 123

    def test_normalize_url_unicode_valid(self):
        """normalize_url_unicode normalizes to NFC."""
        from urlps._security import normalize_url_unicode
        result = normalize_url_unicode("https://example.com")
        assert result == "https://example.com"

    def test_redact_url_for_logs_error_handling(self):
        """Line 1532: ValueError in redact_url_for_logs returns original."""
        from urlps._security import redact_url_for_logs
        # Non-string input
        result = redact_url_for_logs(None)
        assert result is None

    def test_collect_security_findings_no_scheme(self):
        """Line 1573: URL without :// skips host/path checks."""
        from urlps._security import collect_security_findings
        from urlps._security.policy import SecurityPolicy
        findings = collect_security_findings("example.com/path", policy=SecurityPolicy.strict())
        # Should not crash and may have findings for double encoding etc
        assert isinstance(findings, list)

    def test_collect_security_findings_port_value_error(self):
        """Lines 1599-1600: ValueError on bad port handled gracefully."""
        from urlps._security import collect_security_findings
        from urlps._security.policy import SecurityPolicy
        policy = SecurityPolicy.strict()
        # A URL with a non-numeric port causes urlsplit to raise ValueError
        # We test that collect_security_findings handles it gracefully
        findings = collect_security_findings(
            "http://example.com:badport/path",
            policy=policy,
        )
        assert isinstance(findings, list)

    def test_security_get_cache_info(self):
        """Line 1673: get_cache_info returns security function stats."""
        from urlps._security import get_cache_info
        info = get_cache_info()
        assert isinstance(info, dict)
        assert len(info) > 0

    def test_security_clear_caches(self):
        """Line 1682->1681: clear_caches returns previous sizes."""
        from urlps._security import clear_caches, is_ssrf_risk
        is_ssrf_risk("example.com")
        result = clear_caches()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_dns_rate_limiter_get_stats(self):
        """Line 763: DNSRateLimiter.get_stats() returns expected keys."""
        from urlps._security import DNSRateLimiter
        limiter = DNSRateLimiter()
        stats = limiter.stats()
        assert "tokens" in stats
        assert "tracked_hosts" in stats
        assert "total_recent_lookups" in stats
