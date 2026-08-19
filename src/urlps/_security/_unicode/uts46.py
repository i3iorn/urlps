"""A single IDNA/UTS-46 entry point for the whole package.

The parser and the Validator must never disagree on a host's ASCII form --
that would be a parser differential letting a caller allowlist on one
spelling while the URL actually resolves via another:

    https://straße.de/   stdlib IDNA 2003  -> "strasse.de"
                         UTS-46            -> "xn--strae-oqa.de"

Browsers use the second. A caller allowlisting on ``url.host`` would admit a
URL that navigates somewhere else entirely.

``idna`` stays an optional dependency (it is in the ``[idna]`` extra). When it
is missing this module falls back to the stdlib codec **in one place**, warns
once at import so the degradation is visible rather than silent, and reports
via :data:`UTS46_AVAILABLE` so callers can downgrade the checks that genuinely
cannot be done without it instead of quietly returning a different answer.
"""

from __future__ import annotations

import warnings
from functools import lru_cache

from ..._cache_config import VALIDATION_CACHE_SIZE

__all__ = [
    "UTS46_AVAILABLE",
    "IdnaError",
    "to_ascii",
]

try:
    import idna as _idna

    UTS46_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the install
    _idna = None  # type: ignore[assignment]
    UTS46_AVAILABLE = False


#: Raised for a host that IDNA rejects outright. Callers map this to a
#: structured finding rather than letting the underlying library's own
#: exception type leak out.
class IdnaError(ValueError):
    """A host could not be encoded under IDNA/UTS-46."""


_FALLBACK_WARNING = (
    "urlps: the 'idna' package is not installed, so hostname encoding falls back to "
    "the standard library's IDNA 2003 codec. This resolves some internationalized "
    "hosts differently from browsers (for example 'straße.de' becomes 'strasse.de' "
    "rather than 'xn--strae-oqa.de'), and UTS-46 mapping of confusable delimiters "
    "is unavailable. Install urlps[idna] for spec-conformant behaviour."
)

if not UTS46_AVAILABLE:  # pragma: no cover - depends on the install
    warnings.warn(_FALLBACK_WARNING, RuntimeWarning, stacklevel=2)


@lru_cache(maxsize=VALIDATION_CACHE_SIZE)
def to_ascii(host: str) -> str:
    """Encode ``host`` to its A-label (Punycode) form.

    Uses UTS-46 non-transitional processing when ``idna`` is available, which
    is what browsers implement. Falls back to the stdlib IDNA 2003 codec
    otherwise -- see the module docstring for what that costs.
    """
    if not host:
        raise IdnaError("empty host")

    # An all-ASCII host has no IDNA work to do beyond case folding, which the
    # caller's normalization already handled. Skipping the encoder here keeps
    # the common path free of both the import and the table lookups.
    if host.isascii():
        return host

    if UTS46_AVAILABLE:
        try:
            return _idna.encode(host, uts46=True, transitional=False).decode("ascii")
        except _idna.IDNAError as exc:
            raise IdnaError(str(exc)) from exc

    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError) as exc:  # pragma: no cover - fallback path
        raise IdnaError(str(exc)) from exc


@lru_cache(maxsize=VALIDATION_CACHE_SIZE)
def to_unicode(host: str) -> str:
    """Decode ``host`` from its A-label form back to U-labels.

    Used by the homograph checks, which must analyse the *decoded* form:
    Punycode is pure ASCII, so script analysis of ``xn--pypal-4ve.com`` sees
    nothing suspicious while the label it encodes is ``pаypal`` with a
    Cyrillic а.

    Returns ``host`` unchanged when it cannot be decoded -- an undecodable
    label is handled by the validators, not here.
    """
    if "xn--" not in host.lower():
        return host

    if UTS46_AVAILABLE:
        try:
            return _idna.decode(host)
        except _idna.IDNAError:
            return host

    try:  # pragma: no cover - fallback path
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host
