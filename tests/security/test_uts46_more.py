"""Coverage for the stdlib IDNA fallback path in _security/_unicode/uts46.py.

These branches only run when the optional ``idna`` package is absent, which
this environment installs. Simulate that by patching UTS46_AVAILABLE off.
"""

from __future__ import annotations

import pytest

from urlps._security._unicode import uts46


@pytest.fixture(autouse=True)
def _clear_caches():
    uts46.to_ascii.cache_clear()
    uts46.to_unicode.cache_clear()
    yield
    uts46.to_ascii.cache_clear()
    uts46.to_unicode.cache_clear()


def test_to_ascii_uses_stdlib_fallback_when_idna_unavailable(monkeypatch):
    monkeypatch.setattr(uts46, "UTS46_AVAILABLE", False)
    result = uts46.to_ascii("münchen.de")
    assert result == "xn--mnchen-3ya.de"


def test_to_ascii_stdlib_fallback_raises_idna_error_on_failure(monkeypatch):
    monkeypatch.setattr(uts46, "UTS46_AVAILABLE", False)
    with pytest.raises(uts46.IdnaError):
        uts46.to_ascii("≠" * 300)


def test_to_unicode_uses_stdlib_fallback_when_idna_unavailable(monkeypatch):
    monkeypatch.setattr(uts46, "UTS46_AVAILABLE", False)
    result = uts46.to_unicode("xn--mnchen-3ya.de")
    assert result == "münchen.de"


def test_to_unicode_stdlib_fallback_returns_input_on_failure(monkeypatch):
    monkeypatch.setattr(uts46, "UTS46_AVAILABLE", False)
    result = uts46.to_unicode("xn--not-valid-punycode-@@@")
    assert result == "xn--not-valid-punycode-@@@"
