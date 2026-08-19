"""Unicode-aware host findings: mixed scripts, confusables, invisible characters.

Policy-facing layer over :mod:`urlps._security._unicode`. Punycode is ASCII,
and homograph attacks are delivered A-label-encoded (that is what actually
goes on the wire), so everything here decodes Punycode *first*, then
analyses per label -- never on the raw ASCII form.
"""

from __future__ import annotations

from functools import lru_cache

from .._cache_config import SECURITY_CACHE_SIZE
from ..exceptions import ErrorCode
from ._unicode import (
    is_single_script_label,
    is_whole_script_confusable,
    to_unicode,
)

__all__ = [
    "HostFinding",
    "analyze_host",
]

#: Bidi controls: RTL/LTR embeddings, overrides and isolates. In a hostname
#: these exist only to make the rendered text disagree with the parsed text.
#:
#: Written as escapes rather than literals deliberately. These characters are
#: invisible, so a source file containing them cannot be reviewed reliably --
#: which is the Trojan Source attack (CVE-2021-42574) and is exactly what
#: bandit's B613 flags.
_BIDI_CONTROLS = frozenset(
    {
        "\u202a",  # LEFT-TO-RIGHT EMBEDDING
        "\u202b",  # RIGHT-TO-LEFT EMBEDDING
        "\u202c",  # POP DIRECTIONAL FORMATTING
        "\u202d",  # LEFT-TO-RIGHT OVERRIDE
        "\u202e",  # RIGHT-TO-LEFT OVERRIDE
        "\u2066",  # LEFT-TO-RIGHT ISOLATE
        "\u2067",  # RIGHT-TO-LEFT ISOLATE
        "\u2068",  # FIRST STRONG ISOLATE
        "\u2069",  # POP DIRECTIONAL ISOLATE
    }
)

#: Zero-width and invisible formatting characters. Legitimate in some scripts
#: mid-word, but in a hostname they are used to split a label visually without
#: splitting it structurally.
_ZERO_WIDTH = frozenset(
    {
        "\u200b",  # ZERO WIDTH SPACE
        "\u200c",  # ZERO WIDTH NON-JOINER
        "\u200d",  # ZERO WIDTH JOINER
        "\u2060",  # WORD JOINER
        "\ufeff",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    }
)

#: (code, severity, message) for each condition analyze_host can report.
HostFinding = tuple[ErrorCode, str, str]


def _strip_brackets(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


@lru_cache(maxsize=SECURITY_CACHE_SIZE)
def analyze_host(host: str) -> tuple[HostFinding, ...]:
    """Return the Unicode-related findings for ``host``.

    Pure and cached: the caller decides which findings its policy acts on.
    """
    if not host:
        return ()

    inner = _strip_brackets(host)
    # An IPv6 literal has no labels to analyse and no scripts to mix.
    if inner != host:
        return ()

    findings: list[HostFinding] = []

    # Decode before anything else -- see the module docstring.
    decoded = to_unicode(host)

    if "xn--" in host.lower() and decoded == host:
        # to_unicode() returns its input unchanged when decoding fails, which
        # for an xn-- label means the Punycode itself is malformed.
        findings.append(
            (
                ErrorCode.INVALID_PUNYCODE,
                "critical",
                "URL host contains an 'xn--' label that is not valid Punycode.",
            )
        )
        return tuple(findings)

    if any(char in _BIDI_CONTROLS for char in decoded):
        findings.append(
            (
                ErrorCode.BIDI_CONTROL_IN_HOST,
                "critical",
                "URL host contains bidirectional control characters, which make the "
                "displayed hostname differ from the one that is actually resolved.",
            )
        )

    if any(char in _ZERO_WIDTH for char in decoded):
        findings.append(
            (
                ErrorCode.ZERO_WIDTH_IN_HOST,
                "critical",
                "URL host contains zero-width or invisible characters.",
            )
        )

    for label in decoded.split("."):
        if not label:
            continue

        if not is_single_script_label(label):
            findings.append(
                (
                    ErrorCode.MIXED_SCRIPT_LABEL,
                    "major",
                    f"URL host label {label!r} contains mixed Unicode scripts, the signature of a homograph attack.",
                )
            )
            # One report per host is enough; a second mixed label adds noise,
            # not information.
            break

    for label in decoded.split("."):
        if label and is_whole_script_confusable(label):
            findings.append(
                (
                    ErrorCode.CONFUSABLE_HOST,
                    "major",
                    f"URL host label {label!r} is written entirely in a non-Latin script "
                    "but reads as Latin characters.",
                )
            )
            break

    return tuple(findings)
