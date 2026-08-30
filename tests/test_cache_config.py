"""Tests for environment-driven cache size resolution."""

from __future__ import annotations

from urlps._cache_config import _cache_size


def test_cache_size_uses_default_when_env_var_unset(monkeypatch) -> None:
    monkeypatch.delenv("URLPS_TEST_CACHE_SIZE", raising=False)
    assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 42


def test_cache_size_parses_valid_env_var(monkeypatch) -> None:
    monkeypatch.setenv("URLPS_TEST_CACHE_SIZE", "128")
    assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 128


def test_cache_size_falls_back_on_non_integer(monkeypatch) -> None:
    monkeypatch.setenv("URLPS_TEST_CACHE_SIZE", "not-a-number")
    assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 42


def test_cache_size_falls_back_on_non_positive_value(monkeypatch) -> None:
    monkeypatch.setenv("URLPS_TEST_CACHE_SIZE", "0")
    assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 42

    monkeypatch.setenv("URLPS_TEST_CACHE_SIZE", "-5")
    assert _cache_size("URLPS_TEST_CACHE_SIZE", 42) == 42
