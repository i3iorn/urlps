"""Additional coverage for _parser.py: cache diagnostics and query validation."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from urlps import _parser
from urlps.exceptions import QueryParsingError


def test_parse_query_string_rejects_invalid_characters():
    with pytest.raises(QueryParsingError, match="invalid characters"):
        _parser.parse_query_string("key=\x00value")


def test_get_cache_info_skips_functions_without_cache_info(monkeypatch):
    plain_function = MagicMock(spec=[])  # no cache_info attribute
    monkeypatch.setattr(_parser, "_CACHED_FUNCTIONS", [plain_function])
    assert _parser.get_cache_info() == {}


def test_clear_caches_skips_functions_without_cache_info(monkeypatch):
    plain_function = MagicMock(spec=[])  # no cache_info attribute
    monkeypatch.setattr(_parser, "_CACHED_FUNCTIONS", [plain_function])
    assert _parser.clear_caches() == {}
