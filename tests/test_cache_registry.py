"""Every lru_cache in the package must be reachable from get_cache_info().

``_resolve_named_policy`` was cached but absent from both ``get_cache_info()``
and ``clear_all_caches()``, so it could neither be observed nor cleared. That
is the kind of omission nobody notices until they are debugging a memory
profile or trying to get a deterministic benchmark.

This test discovers caches by walking the package rather than comparing
against a hardcoded list, so a cache added later is covered automatically --
which is the only way this class of bug stays fixed.
"""

from __future__ import annotations

import importlib
import pkgutil

import pytest

import urlps


def _is_ours(fn) -> bool:
    """Ignore cached callables imported from the stdlib (e.g. urllib.parse.urlsplit)."""
    return getattr(fn.__wrapped__, "__module__", "").startswith("urlps")


def _normalize_name(name: str) -> str:
    """Collapse the ``_x_cached`` / ``_x`` private spellings onto the reported name."""
    return name.strip("_").removesuffix("_cached")


def _iter_cached_callables():
    """Yield (module_name, qualname, fn) for every lru_cache-wrapped callable."""
    seen: set[int] = set()
    for module_info in pkgutil.walk_packages(urlps.__path__, prefix="urlps."):
        try:
            module = importlib.import_module(module_info.name)
        except ImportError:  # pragma: no cover - optional deps
            continue

        for attr_name in dir(module):
            value = getattr(module, attr_name, None)
            if not callable(value) or id(value) in seen:
                continue
            if not (hasattr(value, "cache_info") and hasattr(value, "__wrapped__")):
                continue
            if not _is_ours(value):
                continue
            seen.add(id(value))
            yield module_info.name, value.__wrapped__.__name__, value

        # Cached staticmethods on classes (Validator) are not module attrs.
        for attr_name in dir(module):
            cls = getattr(module, attr_name, None)
            if not isinstance(cls, type) or cls.__module__ != module_info.name:
                continue
            for member_name in dir(cls):
                member = getattr(cls, member_name, None)
                if not callable(member) or id(member) in seen:
                    continue
                if not (hasattr(member, "cache_info") and hasattr(member, "__wrapped__")):
                    continue
                if not _is_ours(member):
                    continue
                seen.add(id(member))
                yield module_info.name, member.__wrapped__.__name__, member


def _reported_names() -> set[str]:
    names: set[str] = set()
    for group in urlps.get_cache_info().values():
        if isinstance(group, dict):
            names.update(_normalize_name(name) for name in group)
    return names


def test_there_are_caches_to_check() -> None:
    """Guard the guard: a discovery bug must not make this suite vacuously pass."""
    assert len(list(_iter_cached_callables())) >= 10


@pytest.mark.parametrize(
    "qualname",
    sorted({qualname for _, qualname, _ in _iter_cached_callables()}),
)
def test_every_cache_is_reported(qualname: str) -> None:
    assert _normalize_name(qualname) in _reported_names(), (
        f"{qualname!r} is lru_cached but does not appear in get_cache_info(); "
        f"add it to the relevant _CACHED_FUNCTIONS list"
    )


def test_clear_all_caches_reports_the_same_shape() -> None:
    urlps.parse_url("https://example.com/a?b=1")
    before = urlps.get_cache_info()
    cleared = urlps.clear_all_caches()
    assert set(cleared) == set(before)


def test_clear_all_caches_actually_empties_them() -> None:
    urlps.parse_url("https://example.com/a?b=1")
    urlps.clear_all_caches()
    for group in urlps.get_cache_info().values():
        for name, stats in group.items():
            if isinstance(stats, dict):
                assert stats["currsize"] == 0, f"{name} was not cleared"


def test_policy_cache_is_reported() -> None:
    """The specific omission that motivated this module."""
    assert _normalize_name("_resolve_named_policy") in _reported_names()
