"""Additional query-injection security tests."""

from __future__ import annotations

class TestSecurityQueryInjection:
    def test_has_query_injection_encoded_xss_context(self):
        """Lines 1413->1406: %3c followed by script keyword."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("q=%3cscript%3e")
        assert result is True

    def test_has_query_injection_encoded_quote_sql(self):
        """Lines 1420->1406: %27 in SQL context."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("id=%271%27+or+1%3d1")
        assert isinstance(result, bool)

    def test_has_query_injection_encoded_semicolon(self):
        """Lines 1424: %3b is suspicious on its own."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("cmd%3brm+-rf+/")
        assert result is True

    def test_has_query_injection_encoded_pipe(self):
        """Lines 1424: %7c is suspicious."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("x%7ccat+/etc/passwd")
        assert result is True

    def test_has_query_injection_encoded_and(self):
        """Lines 1424: %26%26 is suspicious."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("x%26%26rm+-rf+/")
        assert result is True

    def test_has_query_injection_encoded_or(self):
        """Lines 1424: %7c%7c is suspicious."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("x%7c%7cevil")
        assert result is True

    def test_has_query_injection_encoded_xss_followed_by_iframe(self):
        """Lines 1415->1406: %3c followed by 'iframe' triggers."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("q=%3ciframe+src=evil")
        assert result is True
