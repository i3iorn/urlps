"""Tests for parser confusion detection."""
import pytest
from urlps import parse_url, InvalidURLError
from urlps._security import has_parser_confusion


class TestParserConfusion:
    """Test parser confusion attack detection."""

    def test_multiple_at_signs(self):
        """Multiple @ signs should be detected."""
        assert has_parser_confusion("http://foo@evil.com:80@127.0.0.1/")
        assert has_parser_confusion("http://user@pass@example.com/")
        assert has_parser_confusion("http://a@b@c@example.com/")

    def test_single_at_sign_allowed(self):
        """Single @ sign (normal userinfo) should be allowed."""
        assert not has_parser_confusion("http://user:pass@example.com/")
        assert not has_parser_confusion("http://admin@example.com/")

    def test_backslash_in_authority(self):
        """Backslash in authority section should be detected."""
        assert has_parser_confusion("http://example.com\\admin/")
        assert has_parser_confusion("http://user@example.com\\path/")
        assert has_parser_confusion("http://example.com:80\\test/")

    def test_mixed_separators(self):
        """Mixed forward slash and backslash should be detected."""
        assert has_parser_confusion("http://example.com/path\\file")
        assert has_parser_confusion("http://example.com\\path/file")

    def test_special_chars_in_credentials(self):
        """Special characters in userinfo that might confuse parsers."""
        assert has_parser_confusion("http://user/name@example.com/")
        assert has_parser_confusion("http://user\\name@example.com/")
        assert has_parser_confusion("http://user#name@example.com/")
        assert has_parser_confusion("http://user?name@example.com/")

    def test_normal_credentials_allowed(self):
        """Normal credentials should not trigger confusion."""
        assert not has_parser_confusion("http://admin:secret123@example.com/")
        assert not has_parser_confusion("http://user_name@example.com/")
        assert not has_parser_confusion("http://user:password@example.com/")

    def test_at_sign_in_password_flagged(self):
        """@ sign in password is flagged as potentially confusing."""
        assert has_parser_confusion("http://user:p@ssw0rd@example.com/")

    def test_normal_urls(self):
        """Normal URLs should not trigger confusion."""
        assert not has_parser_confusion("http://example.com/")
        assert not has_parser_confusion("https://example.com/path")
        assert not has_parser_confusion("http://example.com:8080/")
        assert not has_parser_confusion("http://192.168.1.1/")
        assert not has_parser_confusion("http://[::1]/")

    def test_edge_cases(self):
        """Test edge cases."""
        assert not has_parser_confusion("")
        assert not has_parser_confusion("example.com")
        assert not has_parser_confusion(None)  # Should handle gracefully

    def test_parse_url_blocks_confusion(self):
        """parse_url should block parser confusion attacks."""
        with pytest.raises(InvalidURLError, match="parser confusion"):
            parse_url("http://foo@evil.com:80@127.0.0.1/")

        with pytest.raises(InvalidURLError, match="parser confusion"):
            parse_url("http://example.com\\admin/")

        with pytest.raises(InvalidURLError, match="parser confusion"):
            parse_url("http://user/name@example.com/")

    def test_valid_urls_pass(self):
        """Valid URLs should parse successfully."""
        url = parse_url("https://user:pass@example.com:8080/path")
        assert url.host == "example.com"
        assert url.port == 8080

        url2 = parse_url("https://example.com/path?query=value")
        assert url2.host == "example.com"


class TestParserConfusionBypassAttempts:
    """Test real-world bypass attempts."""

    def test_ssrf_bypass_attempt_1(self):
        """SSRF bypass: http://attacker.com@127.0.0.1/"""
        with pytest.raises(InvalidURLError):
            parse_url("http://attacker.com@127.0.0.1/")

    def test_ssrf_bypass_attempt_2(self):
        """SSRF bypass: http://foo@evil.com:80@localhost/"""
        with pytest.raises(InvalidURLError):
            parse_url("http://foo@evil.com:80@localhost/")

    def test_windows_path_confusion(self):
        """Windows path confusion with backslash."""
        with pytest.raises(InvalidURLError):
            parse_url("http://example.com\\\\internal\\share/")

    def test_mixed_separator_confusion(self):
        """Mixed separators to confuse parsers."""
        with pytest.raises(InvalidURLError):
            parse_url("http://example.com/path\\..\\admin/")
