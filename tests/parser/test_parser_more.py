"""Additional coverage for _parser.py: cache diagnostics and query validation."""

from __future__ import annotations

import pytest

from urlps import _parser
from urlps.exceptions import QueryParsingError


def test_parse_query_string_rejects_invalid_characters():
    with pytest.raises(QueryParsingError, match="invalid characters"):
        _parser.parse_query_string("key=\x00value")


def test_parser_cache_info_reads_the_registry():
    info = _parser.get_cache_info()
    assert {"normalize_path", "normalize_host", "normalize_percent_encoding"} <= set(info)
    assert set(_parser.clear_caches()) == set(info)
