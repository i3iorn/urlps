"""Tests for URL.get_query_param()/get_query_param_all()."""

from __future__ import annotations

from urlps import parse_url


class TestGetQueryParam:
    def test_returns_first_value_for_key(self):
        url = parse_url("https://example.com/?id=1&id=2")
        assert url.get_query_param("id") == "1"

    def test_returns_none_for_valueless_flag(self):
        """A key present with no '=value' has value None -- distinct from absent."""
        url = parse_url("https://example.com/?flag")
        assert url.get_query_param("flag") is None

    def test_returns_default_for_missing_key(self):
        url = parse_url("https://example.com/?a=1")
        assert url.get_query_param("missing") is None
        assert url.get_query_param("missing", default="fallback") == "fallback"

    def test_no_query_string_at_all(self):
        url = parse_url("https://example.com/path")
        assert url.get_query_param("anything") is None
        assert url.get_query_param("anything", default="x") == "x"

    def test_decodes_percent_encoded_value(self):
        url = parse_url("https://example.com/?q=hello%20world")
        assert url.get_query_param("q") == "hello world"


class TestGetQueryParamAll:
    def test_returns_all_values_in_order(self):
        url = parse_url("https://example.com/?id=1&id=2&id=3")
        assert url.get_query_param_all("id") == ["1", "2", "3"]

    def test_returns_empty_list_for_missing_key(self):
        url = parse_url("https://example.com/?a=1")
        assert url.get_query_param_all("missing") == []

    def test_single_occurrence_returns_single_element_list(self):
        url = parse_url("https://example.com/?a=1&b=2")
        assert url.get_query_param_all("a") == ["1"]

    def test_mix_of_valued_and_valueless_occurrences(self):
        url = parse_url("https://example.com/?flag&flag=1")
        assert url.get_query_param_all("flag") == [None, "1"]

    def test_no_query_string_at_all(self):
        url = parse_url("https://example.com/path")
        assert url.get_query_param_all("anything") == []
