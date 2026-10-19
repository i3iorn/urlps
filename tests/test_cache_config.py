"""Tests for environment-driven cache size resolution."""

from __future__ import annotations

import warnings

import pytest

from urlps._cache_config import _cache_size


def test_cache_size_uses_default_when_env_var_unset(monkeypatch) -> None:
    monkeypatch.delenv("URLPS_TEST_CACHE_SIZE", raising=False)
    assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 42


def test_cache_size_parses_valid_env_var(monkeypatch) -> None:
    monkeypatch.setenv("URLPS_TEST_CACHE_SIZE", "128")
    assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 128


class TestInvalidValuesWarn:
    """Invalid values fall back to the default -- audibly, like the URLPS_MAX_*
    constants' env helpers, instead of silently. A silent fallback makes a
    mistyped tuning value (say, ``URLPS_CACHE_SIZE_PARSER=1O24``) invisible."""

    def test_non_integer_warns_and_falls_back(self, monkeypatch) -> None:
        monkeypatch.setenv("URLPS_TEST_CACHE_SIZE", "not-a-number")
        with pytest.warns(RuntimeWarning, match="must be an integer"):
            assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 42

    def test_non_positive_value_warns_and_falls_back(self, monkeypatch) -> None:
        monkeypatch.setenv("URLPS_TEST_CACHE_SIZE", "0")
        with pytest.warns(RuntimeWarning, match="must be a positive integer"):
            assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 42

        monkeypatch.setenv("URLPS_TEST_CACHE_SIZE", "-5")
        with pytest.warns(RuntimeWarning, match="must be a positive integer"):
            assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 42


class TestOversizedValuesClamp:
    """A cache size is memory the process pins for its whole life: maxsize x
    (key + result), with keys up to CACHE_MAX_KEY_LENGTH long. An env value of
    "999999999" would previously be honored as-is, reintroducing exactly the
    attacker-key memory-pinning issue the key-length guard exists for -- so
    oversized values are clamped (with a warning) instead of honored."""

    def test_entry_ceiling_clamps_with_warning(self, monkeypatch) -> None:
        monkeypatch.setenv("URLPS_TEST_CACHE_SIZE", "999999999")
        with pytest.warns(RuntimeWarning, match="exceeds the ceiling"):
            assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 65_536

    def test_entry_ceiling_allows_values_at_the_limit(self, monkeypatch) -> None:
        monkeypatch.setenv("URLPS_TEST_CACHE_SIZE", "65536")
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # a value at the ceiling must not warn
            assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 65_536

    def test_key_length_ceiling_is_tighter_than_the_entry_ceiling(self, monkeypatch) -> None:
        # The key-length guard bounds pinned memory per entry; raising it to a
        # URL-length cap (32 KiB) turns the guard off entirely. 8192 is the
        # ceiling, not 65536.
        monkeypatch.setenv("URLPS_TEST_CACHE_MAX_KEY", "999999999")
        with pytest.warns(RuntimeWarning, match="exceeds the ceiling"):
            assert _cache_size("URLPS_TEST_CACHE_MAX_KEY", 1024, 8192) == 8192
