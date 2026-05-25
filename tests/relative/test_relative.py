"""Tests for relative URL reference parsing and building."""
import pytest

from urlps._relative import (
    parse_relative_reference,
    build_relative_reference,
    round_trip_relative,
)
from urlps.exceptions import InvalidURLError


class TestParseRelativeReference:
    """Tests for parse_relative_reference function."""

    def test_simple_path(self):
        """Simple path should be parsed correctly."""
        result = parse_relative_reference("/path/to/resource")
        assert result["path"] == "/path/to/resource"
        assert result["query"] is None
        assert result["fragment"] is None

    def test_path_with_query(self):
        """Path with query string should be parsed correctly."""
        result = parse_relative_reference("/path?foo=bar")
        assert result["path"] == "/path"
        assert result["query"] == "foo=bar"
        assert result["fragment"] is None

    def test_path_with_fragment(self):
        """Path with fragment should be parsed correctly."""
        result = parse_relative_reference("/path#section")
        assert result["path"] == "/path"
        assert result["query"] is None
        assert result["fragment"] == "section"

    def test_path_with_query_and_fragment(self):
        """Path with both query and fragment should be parsed correctly."""
        result = parse_relative_reference("/path?foo=bar#section")
        assert result["path"] == "/path"
        assert result["query"] == "foo=bar"
        assert result["fragment"] == "section"

    def test_query_only(self):
        """Query-only reference should work."""
        result = parse_relative_reference("?query=value")
        assert result["path"] == ""
        assert result["query"] == "query=value"
        assert result["fragment"] is None

    def test_fragment_only(self):
        """Fragment-only reference should work."""
        result = parse_relative_reference("#section")
        assert result["path"] == ""
        assert result["query"] is None
        assert result["fragment"] == "section"

    def test_relative_path(self):
        """Relative path without leading slash should work."""
        result = parse_relative_reference("relative/path")
        assert result["path"] == "relative/path"
        assert result["query"] is None
        assert result["fragment"] is None

    def test_parent_path(self):
        """Parent path reference should work."""
        result = parse_relative_reference("../parent")
        assert result["path"] == "../parent"

    def test_current_dir_path(self):
        """Current directory path reference should work."""
        result = parse_relative_reference("./current")
        assert result["path"] == "./current"

    def test_empty_query(self):
        """Empty query string should be preserved."""
        result = parse_relative_reference("/path?")
        assert result["path"] == "/path"
        assert result["query"] == ""

    def test_empty_fragment(self):
        """Empty fragment should be preserved."""
        result = parse_relative_reference("/path#")
        assert result["path"] == "/path"
        assert result["fragment"] == ""

    def test_rejects_scheme_separator(self):
        """URLs with scheme separator should be rejected."""
        with pytest.raises(InvalidURLError) as exc_info:
            parse_relative_reference("http://example.com/path")
        assert "scheme separator" in str(exc_info.value).lower()

    def test_rejects_other_scheme_separator(self):
        """Any URL with :// should be rejected."""
        with pytest.raises(InvalidURLError):
            parse_relative_reference("ftp://files.example.com")

    def test_rejects_empty_string(self):
        """Empty string should be rejected."""
        with pytest.raises(InvalidURLError) as exc_info:
            parse_relative_reference("")
        assert "non-empty" in str(exc_info.value).lower()

    def test_rejects_non_string(self):
        """Non-string input should be rejected."""
        with pytest.raises(InvalidURLError):
            parse_relative_reference(None)  # type: ignore
        with pytest.raises(InvalidURLError):
            parse_relative_reference(123)  # type: ignore
        with pytest.raises(InvalidURLError):
            parse_relative_reference(["path"])  # type: ignore

    def test_colon_in_path_allowed(self):
        """Colon in path (not scheme) should be allowed."""
        result = parse_relative_reference("/path:with:colons")
        assert result["path"] == "/path:with:colons"

    def test_multiple_question_marks(self):
        """Multiple ? should keep first as separator, rest in query."""
        result = parse_relative_reference("/path?a=1?b=2")
        assert result["path"] == "/path"
        assert result["query"] == "a=1?b=2"

    def test_multiple_hash_marks(self):
        """Multiple # should keep first as separator, rest in fragment."""
        result = parse_relative_reference("/path#section#subsection")
        assert result["path"] == "/path"
        assert result["fragment"] == "section#subsection"


class TestBuildRelativeReference:
    """Tests for build_relative_reference function."""

    def test_simple_path(self):
        """Simple path should be built correctly."""
        result = build_relative_reference("/path/to/resource")
        assert result == "/path/to/resource"

    def test_path_with_query(self):
        """Path with query should be built correctly."""
        result = build_relative_reference("/path", query="foo=bar")
        assert result == "/path?foo=bar"

    def test_path_with_fragment(self):
        """Path with fragment should be built correctly."""
        result = build_relative_reference("/path", fragment="section")
        assert result == "/path#section"

    def test_path_with_query_and_fragment(self):
        """Path with both query and fragment should be built correctly."""
        result = build_relative_reference("/path", query="foo=bar", fragment="section")
        assert result == "/path?foo=bar#section"

    def test_empty_path(self):
        """Empty path should work."""
        result = build_relative_reference("")
        assert result == ""

    def test_empty_path_with_query(self):
        """Empty path with query should work."""
        result = build_relative_reference("", query="foo=bar")
        assert result == "?foo=bar"

    def test_empty_path_with_fragment(self):
        """Empty path with fragment should work."""
        result = build_relative_reference("", fragment="section")
        assert result == "#section"

    def test_rejects_non_string_path(self):
        """Non-string path should be rejected."""
        with pytest.raises(InvalidURLError) as exc_info:
            build_relative_reference(None)  # type: ignore
        assert "string" in str(exc_info.value).lower()

        with pytest.raises(InvalidURLError):
            build_relative_reference(123)  # type: ignore

        with pytest.raises(InvalidURLError):
            build_relative_reference(["path"])  # type: ignore

    def test_none_query_not_added(self):
        """None query should not add ?."""
        result = build_relative_reference("/path", query=None)
        assert result == "/path"
        assert "?" not in result

    def test_none_fragment_not_added(self):
        """None fragment should not add #."""
        result = build_relative_reference("/path", fragment=None)
        assert result == "/path"
        assert "#" not in result


class TestRoundTripRelative:
    """Tests for round_trip_relative function."""

    def test_simple_path_round_trip(self):
        """Simple path should round-trip correctly."""
        original = "/path/to/resource"
        assert round_trip_relative(original) == original

    def test_path_with_query_round_trip(self):
        """Path with query should round-trip correctly."""
        original = "/path?foo=bar&baz=qux"
        assert round_trip_relative(original) == original

    def test_path_with_fragment_round_trip(self):
        """Path with fragment should round-trip correctly."""
        original = "/path#section"
        assert round_trip_relative(original) == original

    def test_full_relative_round_trip(self):
        """Full relative reference should round-trip correctly."""
        original = "/path?foo=bar#section"
        assert round_trip_relative(original) == original

    def test_query_only_round_trip(self):
        """Query-only reference should round-trip correctly."""
        original = "?query=value"
        assert round_trip_relative(original) == original

    def test_fragment_only_round_trip(self):
        """Fragment-only reference should round-trip correctly."""
        original = "#section"
        assert round_trip_relative(original) == original

    def test_empty_query_round_trip(self):
        """Empty query should round-trip correctly."""
        original = "/path?"
        assert round_trip_relative(original) == original

    def test_empty_fragment_round_trip(self):
        """Empty fragment should round-trip correctly."""
        original = "/path#"
        assert round_trip_relative(original) == original


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    def test_unicode_in_path(self):
        """Unicode characters in path should work."""
        result = parse_relative_reference("/путь/到/ścieżka")
        assert result["path"] == "/путь/到/ścieżka"

    def test_unicode_in_query(self):
        """Unicode characters in query should work."""
        result = parse_relative_reference("/path?name=日本語")
        assert result["query"] == "name=日本語"

    def test_unicode_in_fragment(self):
        """Unicode characters in fragment should work."""
        result = parse_relative_reference("/path#раздел")
        assert result["fragment"] == "раздел"

    def test_special_characters_preserved(self):
        """Special characters should be preserved as-is."""
        result = parse_relative_reference("/path%20with%20spaces")
        assert result["path"] == "/path%20with%20spaces"

    def test_long_path(self):
        """Long paths should be handled correctly."""
        long_path = "/" + "/".join(f"segment{i}" for i in range(100))
        result = parse_relative_reference(long_path)
        assert result["path"] == long_path

    def test_complex_query(self):
        """Complex query strings should be preserved."""
        query = "a=1&b=2&c=3&arr[]=x&arr[]=y"
        result = parse_relative_reference(f"/path?{query}")
        assert result["query"] == query
