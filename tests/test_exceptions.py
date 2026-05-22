"""Tests for exception handling and formatting."""
from src.urlps.exceptions import (
    URLpError,
    InvalidURLError,
    URLParseError,
    _truncate_value,
    _MAX_VALUE_LENGTH,
)


class TestValueTruncation:
    """Test that large values are truncated in exception messages."""

    def test_short_value_not_truncated(self):
        """Short values should not be truncated."""
        short_value = "http://example.com"
        result = _truncate_value(short_value)
        assert result == repr(short_value)
        assert "..." not in result

    def test_long_value_truncated(self):
        """Values exceeding max length should be truncated."""
        long_value = "x" * 500
        result = _truncate_value(long_value)
        assert len(result) == _MAX_VALUE_LENGTH
        assert result.endswith("...")

    def test_value_at_boundary(self):
        """Value exactly at max length should not be truncated."""
        # Account for repr adding quotes
        boundary_value = "x" * (_MAX_VALUE_LENGTH - 2)  # -2 for quotes
        result = _truncate_value(boundary_value)
        assert "..." not in result

    def test_value_just_over_boundary(self):
        """Value just over max length should be truncated."""
        over_boundary = "x" * (_MAX_VALUE_LENGTH)
        result = _truncate_value(over_boundary)
        assert result.endswith("...")
        assert len(result) == _MAX_VALUE_LENGTH

    def test_exception_str_with_long_value(self):
        """Exception __str__ should truncate long values."""
        long_url = "http://example.com/" + "a" * 500
        exc = URLpError("Test error", value=long_url, component="url")

        error_str = str(exc)
        assert "..." in error_str
        # Should not contain the full long URL
        assert len(error_str) < len(long_url) + 100

    def test_exception_str_with_short_value(self):
        """Exception __str__ should not truncate short values."""
        short_url = "http://example.com/"
        exc = URLpError("Test error", value=short_url, component="url")

        error_str = str(exc)
        assert short_url in error_str
        assert "..." not in error_str or "..." in short_url

    def test_exception_preserves_original_value(self):
        """Original value should be preserved in exception object."""
        long_url = "http://example.com/" + "a" * 500
        exc = URLpError("Test error", value=long_url, component="url")

        # The actual value attribute should be unchanged
        assert exc.value == long_url
        # Only the string representation should be truncated
        assert len(str(exc)) < len(long_url)

    def test_truncation_with_none_value(self):
        """None value should not cause issues."""
        exc = URLpError("Test error", value=None, component="url")
        error_str = str(exc)
        assert "None" in error_str

    def test_truncation_with_non_string_value(self):
        """Non-string values should be handled correctly."""
        exc = URLpError("Test error", value=12345, component="port")
        error_str = str(exc)
        assert "12345" in error_str

    def test_truncation_with_list_value(self):
        """List values should be truncated if repr is too long."""
        long_list = list(range(1000))
        exc = URLpError("Test error", value=long_list)

        error_str = str(exc)
        assert len(error_str) < len(repr(long_list))
        assert "..." in error_str

    def test_invalid_url_error_truncation(self):
        """InvalidURLError should also truncate long values."""
        long_url = "http://example.com/" + "path/" * 100
        exc = InvalidURLError("Invalid URL", value=long_url)

        error_str = str(exc)
        assert "..." in error_str

    def test_url_parse_error_truncation(self):
        """URLParseError should also truncate long values."""
        long_url = "http://example.com/?" + "&".join(f"param{i}=value{i}" for i in range(100))
        exc = URLParseError("Parse error", value=long_url)

        error_str = str(exc)
        assert "..." in error_str


class TestExceptionBasicBehavior:
    """Test basic exception behavior is preserved."""

    def test_exception_message(self):
        """Exception should preserve message."""
        exc = URLpError("Test message")
        assert exc.message == "Test message"
        assert "Test message" in str(exc)

    def test_exception_without_value_or_component(self):
        """Exception without value/component should work."""
        exc = URLpError("Simple error")
        error_str = str(exc)
        assert error_str == "Simple error"
        assert "component=" not in error_str
        assert "value=" not in error_str

    def test_exception_with_component_only(self):
        """Exception with only component should show it."""
        exc = URLpError("Error", component="host")
        error_str = str(exc)
        assert "component='host'" in error_str

    def test_exception_inheritance(self):
        """Exception classes should maintain proper inheritance."""
        assert issubclass(InvalidURLError, URLpError)
        assert issubclass(URLParseError, InvalidURLError)
