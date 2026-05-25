"""Additional parser tests grouped by parser behavior."""

from __future__ import annotations

import pytest

class TestParser:
    def test_parse_regular_host_idna_error(self):
        """Lines 144-145: IDNA encoding failure raises HostValidationError."""
        from urlps._parser import parse_regular_host
        from urlps.exceptions import HostValidationError
        # This host has a label that is too long after IDNA encoding
        long_label = "a" * 64
        with pytest.raises(HostValidationError):
            parse_regular_host(f"{long_label}.com")

    def test_parse_query_string_empty_key_raises(self):
        """Line 230: Query string with empty key raises QueryParsingError."""
        from urlps._parser import parse_query_string
        from urlps.exceptions import QueryParsingError
        with pytest.raises(QueryParsingError):
            parse_query_string("=value")

    def test_apply_port_defaults_no_port_scheme_raises(self):
        """Line 259: file scheme with explicit port raises UnsupportedSchemeError."""
        from urlps._parser import apply_port_defaults
        from urlps.exceptions import UnsupportedSchemeError
        from urlps.constants import SCHEMES_NO_PORT
        # Find a scheme in SCHEMES_NO_PORT to test with
        no_port_scheme = next(iter(SCHEMES_NO_PORT)) if SCHEMES_NO_PORT else None
        if no_port_scheme:
            with pytest.raises(UnsupportedSchemeError):
                apply_port_defaults(no_port_scheme, 80, "example.com")

    def test_apply_port_defaults_port_without_host_raises(self):
        """Line 261: Port set without host raises PortValidationError."""
        from urlps._parser import apply_port_defaults
        from urlps.exceptions import PortValidationError
        with pytest.raises(PortValidationError):
            apply_port_defaults("https", 443, None)

    def test_parser_custom_scheme_getter(self):
        """Line 324: custom_scheme getter returns current value."""
        from urlps._parser import Parser
        parser = Parser()
        assert parser.custom_scheme is False
        parser.custom_scheme = True
        assert parser.custom_scheme is True

    def test_parse_netloc(self):
        """Line 340: parse_netloc returns correct components."""
        from urlps._parser import Parser
        parser = Parser()
        userinfo, host, port = parser.parse_netloc("user:pass@example.com:8080")
        assert host == "example.com"
        assert port == 8080
        assert userinfo == "user:pass"

    def test_parse_netloc_no_port(self):
        """parse_netloc without explicit port."""
        from urlps._parser import Parser
        parser = Parser()
        userinfo, host, port = parser.parse_netloc("example.com")
        assert host == "example.com"
        assert port is None
        assert userinfo is None

    def test_get_cache_info(self):
        """Lines 363-372: get_cache_info() returns normalize_path stats."""
        from urlps._parser import get_cache_info
        info = get_cache_info()
        assert "normalize_path" in info
        assert info["normalize_path"] is not None
        assert "hits" in info["normalize_path"]

    def test_clear_caches(self):
        """Lines 381-386: clear_caches() returns previous sizes."""
        from urlps._parser import clear_caches, normalize_path
        normalize_path("/some/test/path")
        result = clear_caches()
        assert "normalize_path" in result
        assert isinstance(result["normalize_path"], int)

    def test_parse_url_non_string_raises(self):
        """parse_url() with non-string input raises URLParseError."""
        from urlps._parser import parse_url
        from urlps.exceptions import URLParseError
        with pytest.raises(URLParseError):
            parse_url(123)  # type: ignore

    def test_parse_url_whitespace_only_raises(self):
        """parse_url() with whitespace-only string raises URLParseError."""
        from urlps._parser import parse_url
        from urlps.exceptions import URLParseError
        with pytest.raises(URLParseError):
            parse_url("   ")

class TestParserAdditional:
    """Cover remaining _parser.py lines."""

    def test_parse_query_string_double_ampersand_skips_empty(self):
        """Empty chunks (&&) in query string are skipped."""
        from urlps._parser import parse_query_string
        _, pairs = parse_query_string("a=1&&b=2&&c=3")
        keys = [k for k, _ in pairs]
        assert keys == ["a", "b", "c"]

    def test_parser_port_property_after_parse(self):
        """Parser.port property returns the parsed port."""
        from urlps._parser import Parser
        parser = Parser()
        parser.parse("https://example.com:9090/")
        assert parser.port == 9090

    def test_parser_port_property_no_port(self):
        """Parser.port property returns default port after parse."""
        from urlps._parser import Parser
        parser = Parser()
        parser.parse("https://example.com/")
        # Default port for https is 443
        assert parser.port == 443

    def test_get_cache_info_structure(self):
        """get_cache_info() includes normalize_path stats."""
        from urlps._parser import get_cache_info, normalize_path
        normalize_path("/test/path")
        info = get_cache_info()
        stats = info.get("normalize_path")
        assert stats is not None
        assert "hits" in stats
        assert "misses" in stats
        assert "currsize" in stats

    def test_clear_caches_returns_sizes(self):
        """clear_caches() returns previous cache sizes."""
        from urlps._parser import clear_caches, normalize_path
        normalize_path("/another/test/path")
        result = clear_caches()
        assert "normalize_path" in result
        assert isinstance(result["normalize_path"], int)
