#!/usr/bin/env python3
"""Regenerate ``src/urlps/_security/_unicode/_tables.py``.

Development-only; not shipped in the wheel. The generated module is checked in
so that ``urlps`` itself needs no Unicode data dependency at runtime.

``unicodedata`` does not expose the Script or Script_Extensions properties at
all, which is why the pre-1.0 homograph check resorted to taking the first word
of ``unicodedata.name(char)`` and matching it against a hardcoded list of
eleven script names. That is a name-prefix hack: it misses every script outside
the list and misclassifies characters whose names do not begin with a script
name (MATHEMATICAL ..., FULLWIDTH ..., CIRCLED ...).

Source of truth is the ``regex`` package, which ships full UCD property data
and supports ``\\p{scx=...}``. It is a dev dependency only.

Usage:
    python tools/gen_unicode_tables.py

CI re-runs this and fails on any diff, so the checked-in table cannot drift
from the ``regex`` version pinned in the dev extra.
"""

from __future__ import annotations

import subprocess
import sys
import unicodedata
from pathlib import Path

try:
    import regex
except ImportError:  # pragma: no cover - dev tool
    sys.exit("This generator needs the 'regex' package: pip install -e '.[dev]'")

MAX_CODEPOINT = 0x110000

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "src" / "urlps" / "_security" / "_unicode" / "_tables.py"

#: Scripts that carry no identity of their own for UTS-39 purposes: Common
#: (digits, punctuation) and Inherited (combining marks) legitimately appear
#: alongside any script, so they are ignored when deciding whether a label is
#: single-script.
IGNORED_SCRIPTS = ("Common", "Inherited")


def build_script_ranges() -> tuple[list[tuple[int, int, str]], list[str]]:
    """Return (ranges, script_names) where ranges are (start, end_inclusive, script)."""
    candidate_names = _discover_script_names()

    # One C-level scan per script over the whole codepoint space, rather than
    # testing every codepoint against every script matcher (which would be
    # ~150 x 1.1M individual match calls in Python).
    all_chars = "".join(map(chr, range(MAX_CODEPOINT)))
    owner: list[int] = [-1] * MAX_CODEPOINT

    for index, name in enumerate(candidate_names):
        for match in regex.finditer(rf"\p{{Script={name}}}+", all_chars):
            for codepoint in range(match.start(), match.end()):
                owner[codepoint] = index

    ranges: list[tuple[int, int, str]] = []
    current = -1
    start = 0
    for codepoint in range(MAX_CODEPOINT):
        script_index = owner[codepoint]
        if script_index != current:
            if current != -1:
                ranges.append((start, codepoint - 1, candidate_names[current]))
            current = script_index
            start = codepoint
    if current != -1:
        ranges.append((start, MAX_CODEPOINT - 1, candidate_names[current]))

    return ranges, sorted({script for _, _, script in ranges})


def _discover_script_names() -> list[str]:
    """UCD script long names that this ``regex`` build accepts."""
    # Probing beats hardcoding: a new Unicode release adds scripts, and a
    # hardcoded list would silently stop covering them.
    candidates = [
        "Adlam",
        "Ahom",
        "Anatolian_Hieroglyphs",
        "Arabic",
        "Armenian",
        "Avestan",
        "Balinese",
        "Bamum",
        "Bassa_Vah",
        "Batak",
        "Bengali",
        "Bhaiksuki",
        "Bopomofo",
        "Brahmi",
        "Braille",
        "Buginese",
        "Buhid",
        "Canadian_Aboriginal",
        "Carian",
        "Caucasian_Albanian",
        "Chakma",
        "Cham",
        "Cherokee",
        "Chorasmian",
        "Common",
        "Coptic",
        "Cuneiform",
        "Cypriot",
        "Cypro_Minoan",
        "Cyrillic",
        "Deseret",
        "Devanagari",
        "Dives_Akuru",
        "Dogra",
        "Duployan",
        "Egyptian_Hieroglyphs",
        "Elbasan",
        "Elymaic",
        "Ethiopic",
        "Georgian",
        "Glagolitic",
        "Gothic",
        "Grantha",
        "Greek",
        "Gujarati",
        "Gunjala_Gondi",
        "Gurmukhi",
        "Han",
        "Hangul",
        "Hanifi_Rohingya",
        "Hanunoo",
        "Hatran",
        "Hebrew",
        "Hiragana",
        "Imperial_Aramaic",
        "Inherited",
        "Inscriptional_Pahlavi",
        "Inscriptional_Parthian",
        "Javanese",
        "Kaithi",
        "Kannada",
        "Katakana",
        "Kawi",
        "Kayah_Li",
        "Kharoshthi",
        "Khitan_Small_Script",
        "Khmer",
        "Khojki",
        "Khudawadi",
        "Lao",
        "Latin",
        "Lepcha",
        "Limbu",
        "Linear_A",
        "Linear_B",
        "Lisu",
        "Lycian",
        "Lydian",
        "Mahajani",
        "Makasar",
        "Malayalam",
        "Mandaic",
        "Manichaean",
        "Marchen",
        "Masaram_Gondi",
        "Medefaidrin",
        "Meetei_Mayek",
        "Mende_Kikakui",
        "Meroitic_Cursive",
        "Meroitic_Hieroglyphs",
        "Miao",
        "Modi",
        "Mongolian",
        "Mro",
        "Multani",
        "Myanmar",
        "Nabataean",
        "Nag_Mundari",
        "Nandinagari",
        "New_Tai_Lue",
        "Newa",
        "Nko",
        "Nushu",
        "Nyiakeng_Puachue_Hmong",
        "Ogham",
        "Ol_Chiki",
        "Old_Hungarian",
        "Old_Italic",
        "Old_North_Arabian",
        "Old_Permic",
        "Old_Persian",
        "Old_Sogdian",
        "Old_South_Arabian",
        "Old_Turkic",
        "Old_Uyghur",
        "Oriya",
        "Osage",
        "Osmanya",
        "Pahawh_Hmong",
        "Palmyrene",
        "Pau_Cin_Hau",
        "Phags_Pa",
        "Phoenician",
        "Psalter_Pahlavi",
        "Rejang",
        "Runic",
        "Samaritan",
        "Saurashtra",
        "Sharada",
        "Shavian",
        "Siddham",
        "SignWriting",
        "Sinhala",
        "Sogdian",
        "Sora_Sompeng",
        "Soyombo",
        "Sundanese",
        "Syloti_Nagri",
        "Syriac",
        "Tagalog",
        "Tagbanwa",
        "Tai_Le",
        "Tai_Tham",
        "Tai_Viet",
        "Takri",
        "Tamil",
        "Tangsa",
        "Tangut",
        "Telugu",
        "Thaana",
        "Thai",
        "Tibetan",
        "Tifinagh",
        "Tirhuta",
        "Toto",
        "Ugaritic",
        "Vai",
        "Vithkuqi",
        "Wancho",
        "Warang_Citi",
        "Yezidi",
        "Yi",
        "Zanabazar_Square",
    ]
    accepted = []
    for name in candidates:
        try:
            regex.compile(rf"\p{{Script={name}}}")
        except regex.error:
            continue
        accepted.append(name)
    return accepted


def render(ranges: list[tuple[int, int, str]], script_names: list[str]) -> str:
    script_index = {name: i for i, name in enumerate(script_names)}

    starts = [start for start, _, _ in ranges]
    ends = [end for _, end, _ in ranges]
    codes = [script_index[script] for _, _, script in ranges]

    def block(values: list[int]) -> str:
        lines, row = [], []
        for value in values:
            row.append(str(value))
            if len(row) == 16:
                lines.append("    " + " ".join(f"{v}," for v in row))
                row = []
        if row:
            lines.append("    " + " ".join(f"{v}," for v in row))
        return "\n".join(lines)

    return f'''"""Generated Unicode Script table -- do not edit by hand.

Regenerate with ``python tools/gen_unicode_tables.py``. CI fails on any diff,
so this stays in step with the ``regex`` version pinned in the dev extra.

Stored as three parallel arrays of range starts, inclusive ends and script
indices, resolved by :func:`bisect.bisect_right`. That keeps the lookup at
O(log n) with no per-character dict of 290k entries to build at import.

Unicode version: {unicodedata.unidata_version}
Ranges: {len(ranges)}
Scripts: {len(script_names)}
"""

from __future__ import annotations

UCD_VERSION = "{unicodedata.unidata_version}"

#: Scripts with no identity of their own for UTS-39: they legitimately co-occur
#: with any script, so they never make a label "mixed".
IGNORED_SCRIPTS = frozenset({IGNORED_SCRIPTS!r})

SCRIPT_NAMES: tuple[str, ...] = (
{chr(10).join(f'    "{name}",' for name in script_names)}
)

_RANGE_STARTS: tuple[int, ...] = (
{block(starts)}
)

_RANGE_ENDS: tuple[int, ...] = (
{block(ends)}
)

_RANGE_SCRIPTS: tuple[int, ...] = (
{block(codes)}
)
'''


def main() -> int:
    print("Building script ranges (this takes a minute)...", file=sys.stderr)
    ranges, script_names = build_script_ranges()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(render(ranges, script_names), encoding="utf-8")
    print(f"Wrote {OUTPUT} ({len(ranges)} ranges, {len(script_names)} scripts)", file=sys.stderr)

    # Keep the generated file in the repo's own format so CI's format check
    # cannot fail on a file the repo generates itself.
    subprocess.run([sys.executable, "-m", "ruff", "format", str(OUTPUT)], check=False)
    subprocess.run([sys.executable, "-m", "ruff", "check", "--fix", str(OUTPUT)], check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
