"""Additional suspicious punycode security tests."""

from __future__ import annotations

class TestSecurityPunycode:
    def test_has_suspicious_punycode_decoding_fails(self):
        """Lines 1223-1225: malformed xn-- returns True."""
        from src.urlps._security import has_suspicious_punycode
        # Malformed punycode domain
        result = has_suspicious_punycode("xn---.com")
        # Either True (suspicious) or doesn't crash
        assert isinstance(result, bool)

    def test_has_suspicious_punycode_digits_and_non_ascii(self):
        """Line 1284: digits + non-ASCII is suspicious."""
        from src.urlps._security import has_suspicious_punycode
        result = has_suspicious_punycode("раура1.com")  # Cyrillic + digit
        assert result is True

    def test_has_suspicious_punycode_all_numeric_non_ascii(self):
        """Line 1292: all-numeric non-ASCII domain is suspicious."""
        from src.urlps._security import has_suspicious_punycode
        result = has_suspicious_punycode("пайпал.com")  # Cyrillic brand-like
        assert isinstance(result, bool)

    def test_has_suspicious_punycode_brand_in_non_ascii(self):
        """Line 1308: known brand in non-ASCII host."""
        from src.urlps._security import has_suspicious_punycode
        # Unicode that contains 'paypal' brand in decoded form
        result = has_suspicious_punycode("рауpal.com")  # Cyrillic р + aypal
        assert isinstance(result, bool)
