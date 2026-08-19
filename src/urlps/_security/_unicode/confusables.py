"""Whole-script confusable detection.

The attack this closes: ``раураl.com`` is written entirely in Cyrillic, so it
is perfectly *single-script* and the UTS-39 mixed-script check in
:mod:`.scripts` passes it. Only a confusable check catches it -- every one of
its characters merely *looks* like a Latin letter.

Scope, stated plainly: this is a curated Cyrillic/Greek/Armenian -> Latin
homoglyph map, not the full UTS-39 §4 skeleton algorithm. Full UTS-39 needs
the UCD ``confusables.txt`` data file (~6,200 mappings), which is not
derivable from anything in the standard library or from the ``regex`` package;
:mod:`tools.gen_unicode_tables` is structured to emit it once that file is
available, and :func:`skeleton` already implements the algorithm so only the
table needs swapping.

What is here covers the homoglyph sets that real phishing actually uses --
Cyrillic and Greek lookalikes of ASCII letters -- and it is deliberately
conservative: a character is only listed when it is visually indistinguishable
from its Latin counterpart in common fonts, so false positives on legitimate
single-script domains stay near zero.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache

from ..._cache_config import SECURITY_CACHE_SIZE
from .scripts import scripts_of

__all__ = ["is_whole_script_confusable", "skeleton"]

#: Non-Latin characters that are visually identical (not merely similar) to an
#: ASCII letter or digit in common fonts. Sources: UTR-36 §3.1 and the
#: Cyrillic/Greek sections of UCD confusables.txt.
_CONFUSABLE_TO_LATIN: dict[str, str] = {
    # --- Cyrillic ---
    "а": "a",  # а CYRILLIC SMALL LETTER A
    "е": "e",  # е CYRILLIC SMALL LETTER IE
    "о": "o",  # о CYRILLIC SMALL LETTER O
    "р": "p",  # р CYRILLIC SMALL LETTER ER
    "с": "c",  # с CYRILLIC SMALL LETTER ES
    "у": "y",  # у CYRILLIC SMALL LETTER U
    "х": "x",  # х CYRILLIC SMALL LETTER HA
    "ѕ": "s",  # ѕ CYRILLIC SMALL LETTER DZE
    "і": "i",  # і CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    "ј": "j",  # ј CYRILLIC SMALL LETTER JE
    "һ": "h",  # һ CYRILLIC SMALL LETTER SHHA
    "ӏ": "l",  # ӏ CYRILLIC SMALL LETTER PALOCHKA
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    "Ѕ": "S",
    "І": "I",
    "Ј": "J",
    # --- Greek ---
    "α": "a",  # α GREEK SMALL LETTER ALPHA
    "ο": "o",  # ο GREEK SMALL LETTER OMICRON
    "ρ": "p",  # ρ GREEK SMALL LETTER RHO
    "σ": "o",  # σ GREEK SMALL LETTER SIGMA
    "ν": "v",  # ν GREEK SMALL LETTER NU
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
    # --- Armenian ---
    "ո": "n",  # ո ARMENIAN SMALL LETTER VO
    "ռ": "n",  # ռ ARMENIAN SMALL LETTER RA
    "օ": "o",  # օ ARMENIAN SMALL LETTER OH
    "հ": "h",  # հ ARMENIAN SMALL LETTER HO
    "գ": "g",  # գ ARMENIAN SMALL LETTER GIM
    "զ": "q",  # զ ARMENIAN SMALL LETTER ZA
}


@lru_cache(maxsize=SECURITY_CACHE_SIZE)
def skeleton(text: str) -> str:
    """UTS-39 §4 skeleton: the form two confusable strings share.

    ``NFD -> confusable substitution -> NFD``, then case-folded. With the full
    confusables.txt table this is the standard algorithm verbatim; with the
    curated table it is the same algorithm over a smaller mapping.
    """
    decomposed = unicodedata.normalize("NFD", text)
    substituted = "".join(_CONFUSABLE_TO_LATIN.get(char, char) for char in decomposed)
    return unicodedata.normalize("NFD", substituted).casefold()


@lru_cache(maxsize=SECURITY_CACHE_SIZE)
def is_whole_script_confusable(label: str) -> bool:
    """Whether ``label`` is a non-Latin label disguised as a Latin one.

    True when the label contains no Latin at all, yet its skeleton is entirely
    ASCII -- i.e. every meaningful character was a Latin lookalike. That is the
    ``раураl.com`` shape.

    Legitimate non-Latin domains are unaffected: ``пример.рф`` contains
    characters with no Latin lookalike, so its skeleton keeps them and the
    check does not fire.
    """
    if label.isascii():
        return False

    scripts = scripts_of(label)
    # A label that already contains Latin is the mixed-script case, which
    # scripts.is_single_script_label() owns. Checking it here too would report
    # the same host twice under two different codes.
    if not scripts or "Latin" in scripts:
        return False

    reduced = skeleton(label)
    # Ignore the characters that carry no script identity (digits, hyphens).
    meaningful = [char for char in reduced if not char.isdigit() and char != "-"]
    return bool(meaningful) and all(char.isascii() for char in meaningful)
