"""Caches must not let hostile input pin unbounded memory.

Every cached call keeps its key (and result) alive until evicted. With
maximal-length distinct inputs that was ~450 MB for 3,000 canonicalize()
calls against the 8,192-entry query-encode cache, retained for the life of
the process. Caches whose key length is not capped upstream now skip caching
over-long keys; results are unchanged.
"""

from __future__ import annotations

import os
import subprocess
import sys
from urllib.parse import quote_plus

import pytest

from urlps import clear_all_caches, parse_url
from urlps._builder import Builder, _encode_for_query
from urlps._cache_config import CACHE_MAX_KEY_LENGTH, CACHE_MAX_VALUE_KEY_LENGTH
from urlps._normalize import normalize_percent_encoding
from urlps._parser import normalize_path
from urlps._security.ip_utils import is_ssrf_risk
from urlps._security.url_checks import find_authority_marker, has_parser_confusion
from urlps._validation import Validator

ASTRAL = "\U0001f600"  # 4 bytes per code point in a str, 12 chars once percent-encoded

URL_LEVEL = [
    (Validator.is_url_safe_string, lambda n: "a" * n),
    (Validator.is_valid_fragment, lambda n: "a" * n),
    (Validator.is_valid_host, lambda n: "a" * n),
    (Validator.is_valid_ipv4, lambda n: "1" * n),
    (Validator.is_valid_ipv6, lambda n: "[" + "1" * n + "]"),
    (Validator.is_valid_scheme, lambda n: "a" * n),
    (Validator.is_ip_address, lambda n: "1" * n),
    (find_authority_marker, lambda n: "http://" + "a" * n),
    (has_parser_confusion, lambda n: "http://" + "a" * n),
    (normalize_percent_encoding, lambda n: "%41" + "a" * n),
    (normalize_path, lambda n: "/" + "a" * min(n, 4000)),
    (is_ssrf_risk, lambda n: "a" * n),
]


@pytest.fixture(autouse=True)
def _empty_caches():
    clear_all_caches()
    yield
    clear_all_caches()


@pytest.mark.parametrize("cached,make", URL_LEVEL, ids=lambda v: getattr(v, "__name__", ""))
def test_over_long_keys_are_computed_but_not_retained(cached, make) -> None:
    long_key = make(CACHE_MAX_KEY_LENGTH + 1)
    if len(long_key) <= CACHE_MAX_KEY_LENGTH:
        pytest.skip("input capped below the cache bound by the function's own limit")
    before = cached.cache_info().currsize
    first = cached(long_key)
    assert cached(long_key) == first
    assert cached.cache_info().currsize == before


@pytest.mark.parametrize("cached,make", URL_LEVEL, ids=lambda v: getattr(v, "__name__", ""))
def test_ordinary_keys_are_still_cached(cached, make) -> None:
    key = make(8)
    cached(key)
    cached(key)
    assert cached.cache_info().hits >= 1


def test_value_encoders_use_the_tighter_bound() -> None:
    long_value = ASTRAL * (CACHE_MAX_VALUE_KEY_LENGTH + 1)
    assert _encode_for_query(long_value, Builder.QUERY_SAFE) == quote_plus(long_value, safe=Builder.QUERY_SAFE)
    assert _encode_for_query.cache_info().currsize == 0
    Builder._percent_encode_cached(long_value, Builder.PATH_SAFE)
    assert Builder._percent_encode_cached.cache_info().currsize == 0

    _encode_for_query("short", Builder.QUERY_SAFE)
    assert _encode_for_query.cache_info().currsize == 1


def _bounded_caches():
    return [cached for cached, _ in URL_LEVEL] + [_encode_for_query, Builder._percent_encode_cached]


def test_hostile_canonicalize_loop_pins_nothing_in_bounded_caches() -> None:
    """The review's attack: maximal distinct inputs through parse + canonicalize().

    Before this fix each such URL pinned ~150 KB across the caches (~450 MB
    per 3,000). Now every over-long key is computed uncached, so the bounded
    caches hold only the handful of short keys these URLs share.
    """
    for i in range(300):
        parse_url(
            f"https://example.com/{ASTRAL * 2000}{i}?a={ASTRAL * 4000}{i}#{'%F0%9F%98%80' * 300}{i}"
        ).canonicalize()
    sizes = {cached.__wrapped__.__name__: cached.cache_info().currsize for cached in _bounded_caches()}
    assert all(size <= 8 for size in sizes.values()), sizes


def test_worst_case_bounded_cache_footprint_is_small() -> None:
    """Every bounded cache full of maximal keys: maxsize x (key + result) bytes, summed.

    A str key of n code points outside Latin-1 costs 4n bytes. Validators and
    predicates return bool/int; the normalizers return a string no longer
    than their input; the encoders return up to 12 ASCII chars per code point.
    """
    result_bytes_per_code_point = {
        normalize_percent_encoding: 4,
        normalize_path: 4,
        _encode_for_query: 12,
        Builder._percent_encode_cached: 12,
    }
    worst = 0
    for cached in _bounded_caches():
        is_encoder = cached in (_encode_for_query, Builder._percent_encode_cached)
        limit = CACHE_MAX_VALUE_KEY_LENGTH if is_encoder else CACHE_MAX_KEY_LENGTH
        per_entry = limit * (4 + result_bytes_per_code_point.get(cached, 0))
        worst += cached.cache_parameters()["maxsize"] * per_entry
    # ~54 MB with the defaults, against ~1 GB+ before the bound existed.
    assert worst < 64 * 1024 * 1024, f"{worst / 1e6:.0f} MB"


def test_bounds_are_configurable_from_the_environment() -> None:
    env = {**os.environ, "URLPS_CACHE_MAX_KEY_LENGTH": "64", "URLPS_CACHE_MAX_VALUE_KEY_LENGTH": "8"}
    code = "import urlps._cache_config as c; print(c.CACHE_MAX_KEY_LENGTH, c.CACHE_MAX_VALUE_KEY_LENGTH)"
    result = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=True)
    assert result.stdout.split() == ["64", "8"]
