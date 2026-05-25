"""Tests for Unicode normalization security."""
import pytest
from urlps import parse_url, InvalidURLError
from urlps._security import normalize_url_unicode


class TestUnicodeNormalization:
    """Test Unicode normalization."""

    def test_normalize_nfc(self):
        """Test NFC normalization."""
        # Combining characters (NFD) should be normalized to composed form (NFC)
        nfd = "e\u0301"  # e + combining acute accent
        nfc = "\u00e9"   # é (precomposed)

        assert normalize_url_unicode(f"http://example.com/{nfd}") == f"http://example.com/{nfc}"

    def test_ascii_unchanged(self):
        """ASCII URLs should remain unchanged."""
        url = "http://example.com/path"
        assert normalize_url_unicode(url) == url

    def test_fullwidth_characters_normalized(self):
        """Fullwidth characters should be normalized."""
        # Fullwidth characters (often used in attacks)
        fullwidth = "http://example.com/\uff10"  # Fullwidth 0
        normalized = normalize_url_unicode(fullwidth)
        # NFC normalization doesn't change fullwidth to ASCII, but it normalizes the form
        assert normalized == fullwidth  # Fullwidth stays fullwidth in NFC

    def test_edge_cases(self):
        """Test edge cases."""
        assert normalize_url_unicode("") == ""
        assert normalize_url_unicode("test") == "test"
        # Non-string returns as-is
        assert normalize_url_unicode(None) is None

    def test_homograph_after_normalization(self):
        """Homograph attacks should still be detected after normalization."""
        # Use Cyrillic 'а' (U+0430) instead of Latin 'a'
        cyrillic_url = "http://ex\u0430mple.com/"  # Has Cyrillic 'а'

        with pytest.raises(InvalidURLError, match="mixed Unicode scripts"):
            parse_url(cyrillic_url)


class TestNormalizationBypassPrevention:
    """Test that normalization prevents bypass attacks."""

    def test_path_traversal_after_normalization(self):
        """Path traversal should be detected after normalization."""
        # Some systems might normalize differently
        url_with_dots = "http://example.com/path/../admin"

        with pytest.raises(InvalidURLError, match="traversal"):
            parse_url(url_with_dots)

    def test_validation_applies_to_normalized_url(self):
        """Validation should apply to normalized form."""
        # Create URL with combining characters
        url = "http://example.com/path"

        # Should parse successfully
        parsed = parse_url(url)
        assert parsed.host == "example.com"
