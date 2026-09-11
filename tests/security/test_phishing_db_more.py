"""Additional coverage for _security/phishing_db.py hostname parsing edge cases."""

from __future__ import annotations

from urlps._security.phishing_db import PhishingDatabaseManager


class TestParseHostnames:
    def test_skips_blank_lines(self):
        result = PhishingDatabaseManager._parse_hostnames("\n\nexample.com\n\n")
        assert result == {"example.com"}

    def test_skips_overlong_hostnames(self):
        overlong = "a" * 254 + ".com"
        result = PhishingDatabaseManager._parse_hostnames(f"example.com\n{overlong}\n")
        assert result == {"example.com"}

    def test_skips_lines_failing_host_pattern(self):
        result = PhishingDatabaseManager._parse_hostnames("example.com\nnot a valid host!\n")
        assert result == {"example.com"}
