"""Unicode Script resolution and the UTS-39 restriction-level check.

Resolves the real Script property from a generated table and implements
UTS-39 §5.1 Highly Restrictive, applied per label -- so a legitimate IDN like
``例え.com`` is not flagged just because its TLD is Latin.
"""

from __future__ import annotations

from bisect import bisect_right
from functools import lru_cache

from ..._cache_config import SECURITY_CACHE_SIZE
from ._tables import (
    _RANGE_ENDS,
    _RANGE_SCRIPTS,
    _RANGE_STARTS,
    IGNORED_SCRIPTS,
    SCRIPT_NAMES,
    UCD_VERSION,
)

__all__ = [
    "UCD_VERSION",
    "is_single_script_label",
    "script_of",
    "scripts_of",
]

#: Script combinations UTS-39 §5.1 accepts as single-script, because they are
#: how these languages are actually written. Without these, every ordinary
#: Japanese or Korean domain would be flagged as a homograph attack.
_ALLOWED_COMBINATIONS: tuple[frozenset[str], ...] = (
    frozenset({"Latin", "Han", "Hiragana", "Katakana"}),  # Japanese
    frozenset({"Latin", "Han", "Bopomofo"}),  # Chinese
    frozenset({"Latin", "Han", "Hangul"}),  # Korean
)


def script_of(char: str) -> str | None:
    """Return the Unicode Script long name for ``char``, or None if unassigned."""
    codepoint = ord(char)
    index = bisect_right(_RANGE_STARTS, codepoint) - 1
    if index < 0 or codepoint > _RANGE_ENDS[index]:
        return None
    return SCRIPT_NAMES[_RANGE_SCRIPTS[index]]


@lru_cache(maxsize=SECURITY_CACHE_SIZE)
def scripts_of(label: str) -> frozenset[str]:
    """Scripts present in ``label``, excluding Common and Inherited.

    Common (digits, hyphen, punctuation) and Inherited (combining marks)
    legitimately appear in any script, so counting them would make almost every
    label look mixed.
    """
    found = set()
    for char in label:
        script = script_of(char)
        if script is not None and script not in IGNORED_SCRIPTS:
            found.add(script)
    return frozenset(found)


@lru_cache(maxsize=SECURITY_CACHE_SIZE)
def is_single_script_label(label: str) -> bool:
    """Whether ``label`` satisfies UTS-39 §5.1 Highly Restrictive.

    True for a label written in one script, or in one of the language
    combinations Unicode explicitly allows (see ``_ALLOWED_COMBINATIONS``).
    """
    # Fast path: a plain ASCII label can only be Latin/Common and is always
    # single-script. Most hostnames take this branch and never touch the table.
    if label.isascii():
        return True

    scripts = scripts_of(label)
    if len(scripts) <= 1:
        return True

    return any(scripts <= allowed for allowed in _ALLOWED_COMBINATIONS)
