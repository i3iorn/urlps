"""Exercises the idna-absent fallback path in ``_security/_unicode/uts46.py``.

That path (stdlib-only IDNA 2003 encoding/decoding) previously had no test
coverage at all: both branches are marked ``# pragma: no cover - depends on
the install`` because ``idna`` is a hard dev dependency, so no CI job ever
actually ran with it missing. But the module's own docstring documents this
as a real, security-relevant differential -- the same class of bug fixed as
a *security fix* in 1.0.0 (``straße.de`` resolving to ``strasse.de`` under
the stdlib codec vs. the ``xn--strae-oqa.de`` browsers use under UTS-46) --
so it deserves an explicit, deterministic test rather than living untested.

We simulate ``idna`` being absent by making its import raise, then reloading
the ``uts46`` module so its top-level ``try``/``except ImportError`` re-runs
against the stdlib fallback branch, and restore the real module afterward so
later tests keep running with ``idna`` available (every other test in this
suite assumes the ``idna`` extra is installed, which it is via the ``dev``
extra).
"""

from __future__ import annotations

import builtins
import importlib
import sys

import pytest

UTS46_MODULE_NAME = "urlps._security._unicode.uts46"


@pytest.fixture
def uts46_without_idna(monkeypatch):
    """Reload ``uts46`` as if the ``idna`` package were not installed."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "idna" or name.startswith("idna."):
            raise ImportError("simulated: idna is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.delitem(sys.modules, "idna", raising=False)
    monkeypatch.setattr(builtins, "__import__", fake_import)

    module = importlib.import_module(UTS46_MODULE_NAME)
    with pytest.warns(RuntimeWarning, match="idna"):
        reloaded = importlib.reload(module)

    try:
        yield reloaded
    finally:
        # Undo the import patch and the sys.modules deletion first, then
        # reload again so the module (and every already-imported reference
        # to its functions -- they share the same __globals__ dict) is back
        # on the real idna-backed implementation for the rest of the suite.
        monkeypatch.undo()
        importlib.reload(module)


class TestIdnaFallback:
    def test_uts46_unavailable_flag_is_set(self, uts46_without_idna):
        assert uts46_without_idna.UTS46_AVAILABLE is False

    def test_to_ascii_uses_stdlib_idna2003_not_uts46(self, uts46_without_idna):
        """The documented differential: stdlib IDNA2003 vs. UTS-46.

        Browsers (UTS-46) encode this host as ``xn--strae-oqa.de``. The
        stdlib ``idna`` codec -- what this fallback uses -- encodes it as
        ``strasse.de`` instead: a different, and unregistered-in-this-form,
        domain. A caller relying on ``url.host`` for allowlisting under the
        fallback gets the weaker of the two answers, which is exactly what
        the module's docstring warns about.
        """
        assert uts46_without_idna.to_ascii("straße.de") == "strasse.de"

    def test_to_ascii_raises_idna_error_for_invalid_host(self, uts46_without_idna):
        from urlps._security._unicode.uts46 import IdnaError

        with pytest.raises(IdnaError):
            uts46_without_idna.to_ascii("☃" * 300)  # snowman, way past a label limit

    def test_to_unicode_falls_back_gracefully_on_undecodable_label(self, uts46_without_idna):
        # Not a genuine Punycode label; the fallback must not raise, only
        # return the input unchanged (same contract as the idna-backed path).
        assert uts46_without_idna.to_unicode("xn--not-a-real-punycode-label") == "xn--not-a-real-punycode-label"

    def test_ascii_only_hosts_skip_the_encoder_entirely(self, uts46_without_idna):
        # Case-folding is the caller's job; an ASCII host round-trips as-is
        # regardless of whether idna is installed.
        assert uts46_without_idna.to_ascii("example.com") == "example.com"
