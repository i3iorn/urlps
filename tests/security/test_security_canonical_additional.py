"""Additional canonical URL security tests."""

from __future__ import annotations

class TestSecurityCanonical:
    def test_is_non_canonical_url_uppercase_scheme(self):
        """Lines 887->893: uppercase scheme detected as non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("HTTP://example.com/")

    def test_is_non_canonical_url_uppercase_host(self):
        """Lines 897->921: uppercase host detected as non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://EXAMPLE.COM/")

    def test_is_non_canonical_url_default_port(self):
        """Lines 927: default port detected as non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com:80/")

    def test_is_non_canonical_url_dot_segment(self):
        """Lines 949: dot-segment detected as non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/./path")

    def test_is_non_canonical_url_dotdot_segment(self):
        """Lines 951: dotdot-segment detected as non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/path/../other")

    def test_is_non_canonical_url_end_dot_segment(self):
        """Lines 953: path ending with /. is non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/path/.")

    def test_is_non_canonical_url_canonical_returns_false(self):
        """is_non_canonical_url returns False for canonical URL."""
        from src.urlps._security import is_non_canonical_url
        assert not is_non_canonical_url("https://example.com/path")

    def test_is_non_canonical_url_no_scheme(self):
        """is_non_canonical_url returns False for URL without scheme."""
        from src.urlps._security import is_non_canonical_url
        assert not is_non_canonical_url("example.com/path")

    def test_is_non_canonical_url_trailing_dot_host(self):
        """Trailing dot in hostname is non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com./path")

    def test_is_non_canonical_url_lowercase_percent_encoding(self):
        """Lowercase percent-encoding in path is non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/%2fpath")

    def test_is_non_canonical_url_non_canonical_ipv6(self):
        """Non-canonical IPv6 form detected."""
        from src.urlps._security import is_non_canonical_url
        # Non-compressed form when compressed exists
        result = is_non_canonical_url("http://[0:0:0:0:0:0:0:1]/")
        assert result is True

    def test_is_non_canonical_url_fragment_lowercase_encoding(self):
        """Lowercase encoding in fragment is non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/path#%2ffrag")

    def test_is_non_canonical_url_query_lowercase_encoding(self):
        """Lowercase encoding in query string is non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/path?k=%2fval")

class TestGetCanonicalUrl:
    def test_get_canonical_url_uppercase_scheme(self):
        """Lines 1063->1127: lowercases scheme."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("HTTP://EXAMPLE.COM/path")
        assert result is not None
        assert result.startswith("http://")

    def test_get_canonical_url_default_port_removed(self):
        """Lines 1112-1118: removes default port."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com:80/")
        assert result is not None
        assert ":80" not in result

    def test_get_canonical_url_path_normalization(self):
        """Line 1131: path normalization removes dot segments."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com/a/../b")
        assert result is not None
        assert "/a/" not in result
        assert "/b" in result

    def test_get_canonical_url_query_uppercase_encoding(self):
        """Line 1150: uppercase encoding in query."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com/?k=%2fval")
        assert result is not None
        assert "%2F" in result or "%2f" not in result

    def test_get_canonical_url_fragment_uppercase_encoding(self):
        """Line 1158: uppercase encoding in fragment."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com/path#%2ffrag")
        assert result is not None
        assert "%2F" in result or "%2f" not in result

    def test_get_canonical_url_with_userinfo(self):
        """get_canonical_url handles netloc with userinfo."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://user@EXAMPLE.COM/")
        assert result is not None
        assert "user@example.com" in result

    def test_get_canonical_url_invalid_returns_none(self):
        """Lines 1168-1169: invalid URL returns None."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("")
        assert result is None

    def test_get_canonical_url_no_scheme_returns_none(self):
        """get_canonical_url returns None when no scheme."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("example.com/path")
        assert result is None

    def test_get_canonical_url_trailing_dot_removed(self):
        """Line 1095-1096: trailing dot in host removed."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com./path")
        assert result is not None
        assert "example.com." not in result

    def test_get_canonical_url_ipv6_canonicalized(self):
        """Lines 1100-1107: IPv6 address canonicalized."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://[0:0:0:0:0:0:0:1]/")
        assert result is not None
        assert "[::1]" in result

    def test_get_canonical_url_ipv6_with_port(self):
        """Lines 1079: IPv6 with port in netloc."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://[::1]:8080/")
        assert result is not None
        assert "[::1]" in result

    def test_get_canonical_url_ipv6_malformed_uses_hostname(self):
        """Line 1084: malformed IPv6 falls back to hostname."""
        from src.urlps._security import get_canonical_url
        # A netloc starting with [ but not well-formed
        result = get_canonical_url("http://[::1/path")
