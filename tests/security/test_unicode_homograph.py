"""Unicode host analysis: scripts, confusables, UTS-46, and Punycode decoding.

Pins two directions: homograph attacks must be caught even when delivered
A-label-encoded (``xn--pypal-4ve.com`` decodes to ``pаypal`` with a Cyrillic
а), and legitimate per-label single-script IDNs must not be flagged just
because their TLD is Latin.
"""

from __future__ import annotations

import pytest

import urlps
from urlps import ErrorCode, SecurityPolicy, parse_url
from urlps._security._unicode import (
    is_single_script_label,
    is_whole_script_confusable,
    script_of,
    scripts_of,
    to_ascii,
    to_unicode,
)


def _codes(url: str, policy: str = "strict") -> set[str]:
    try:
        parse_url(url, policy=policy)
    except urlps.URLpError as exc:
        return {exc.code.value} if exc.code else set()
    return set()


# ---------------------------------------------------------------------------
# Script property resolution
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "char, expected",
    [
        ("a", "Latin"),
        ("а", "Cyrillic"),  # CYRILLIC SMALL LETTER A
        ("α", "Greek"),  # GREEK SMALL LETTER ALPHA
        ("例", "Han"),
        ("え", "Hiragana"),
        ("한", "Hangul"),
        ("1", "Common"),
        ("-", "Common"),
        # The old first-word-of-unicodedata.name() hack got these wrong: their
        # names begin with FULLWIDTH / MATHEMATICAL, not with a script name.
        ("ａ", "Latin"),  # FULLWIDTH LATIN SMALL LETTER A
        # Script=Common per the UCD despite the name -- the hack would have
        # reported "MATHEMATICAL", which is not a script at all.
        ("\U0001d41a", "Common"),  # MATHEMATICAL BOLD SMALL A
    ],
)
def test_script_of(char: str, expected: str) -> None:
    assert script_of(char) == expected


def test_common_and_inherited_are_not_counted_as_scripts() -> None:
    """Digits and hyphens co-occur with every script; counting them makes everything 'mixed'."""
    assert scripts_of("abc-123") == frozenset({"Latin"})


# ---------------------------------------------------------------------------
# UTS-39 single-script, per label
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label",
    [
        "example",
        "例え",  # Japanese: Han + Hiragana
        "한국",  # Korean
        "онлайн",  # Russian "онлайн"
        "münchen",
        "abc123",
    ],
)
def test_legitimate_labels_are_single_script(label: str) -> None:
    assert is_single_script_label(label)


@pytest.mark.parametrize(
    "label",
    [
        "pаypal",  # Latin + Cyrillic а
        "аpple",  # Cyrillic а + Latin
        "gооgle",  # Cyrillic о x2 + Latin
    ],
)
def test_homograph_labels_are_not_single_script(label: str) -> None:
    assert not is_single_script_label(label)


def test_japanese_domain_is_not_flagged_as_mixed() -> None:
    """Per-label analysis: a Latin TLD must not flag an unrelated non-Latin label."""
    assert is_single_script_label("例え")
    assert not _codes("http://例え.com/")


# ---------------------------------------------------------------------------
# Whole-script confusables
# ---------------------------------------------------------------------------


def test_all_cyrillic_lookalike_is_confusable() -> None:
    """Nothing is *mixed* here -- the whole label is a disguise."""
    assert is_whole_script_confusable("аррӏе")  # аррӏе


@pytest.mark.parametrize(
    "label",
    [
        "онлайн",  # онлайн: л, н, й have no Latin lookalike
        "例え",
        "example",
        "한국",
    ],
)
def test_ordinary_labels_are_not_confusable(label: str) -> None:
    assert not is_whole_script_confusable(label)


def test_mixed_script_labels_are_not_double_reported() -> None:
    """A label containing Latin is the mixed-script case, not the confusable one."""
    assert not is_whole_script_confusable("pаypal")


# ---------------------------------------------------------------------------
# The regression: Punycode must be decoded before analysis
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host, expected_code",
    [
        ("xn--pypal-4ve.com", ErrorCode.MIXED_SCRIPT_LABEL),  # pаypal
        ("xn--pple-43d.com", ErrorCode.MIXED_SCRIPT_LABEL),  # аpple
        ("xn--80ak6aa92e.com", ErrorCode.CONFUSABLE_HOST),  # аррӏе
    ],
)
@pytest.mark.parametrize("policy", ["strict", "balanced"])
def test_punycode_homographs_are_caught(host: str, expected_code: ErrorCode, policy: str) -> None:
    """Punycode is ASCII, so homograph analysis must decode it first."""
    assert expected_code.value in _codes(f"http://{host}/", policy)


@pytest.mark.parametrize(
    "host",
    [
        "xn--r8jz45g.xn--zckzah",  # 例え.テスト
        "xn--3e0b707e.com",  # 한국.com
        "xn--mnchen-3ya.de",  # münchen.de
        "xn--80asehdb.com",  # онлайн.com
    ],
)
def test_legitimate_punycode_domains_still_parse(host: str) -> None:
    assert parse_url(f"http://{host}/").host == host


# ---------------------------------------------------------------------------
# UTS-46 / the IDNA differential
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host, expected",
    [
        # The differential: stdlib IDNA 2003 maps ß -> ss, giving a DIFFERENT
        # domain from the one every browser resolves.
        ("straße.de", "xn--strae-oqa.de"),
        ("faß.de", "xn--fa-hia.de"),
        ("münchen.de", "xn--mnchen-3ya.de"),
        ("example.com", "example.com"),
    ],
)
def test_to_ascii_matches_browser_resolution(host: str, expected: str) -> None:
    assert to_ascii(host) == expected


def test_parser_and_validator_agree_on_idna() -> None:
    """Parser and Validator must resolve a host through the same IDNA path."""
    from urlps._validation import Validator

    host = "straße.de"
    assert parse_url(f"https://{host}/").host == Validator._to_ascii_host(host)


def test_round_trip_decode() -> None:
    assert to_unicode(to_ascii("münchen.de")) == "münchen.de"


# ---------------------------------------------------------------------------
# Invisible / structural characters
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "exa​mple.com",  # zero-width space
        "example.com‍.evil.com",  # zero-width joiner
        "‮example.com",  # RTL override
    ],
)
def test_invisible_and_bidi_characters_are_rejected(host: str) -> None:
    """These were rejected before too, but with code=None -- now they are structured."""
    with pytest.raises(urlps.URLpError):
        parse_url(f"https://{host}/")


# ---------------------------------------------------------------------------
# Policy wiring
# ---------------------------------------------------------------------------


def test_internal_policy_skips_unicode_heuristics() -> None:
    policy = SecurityPolicy.internal()
    assert parse_url("http://xn--pypal-4ve.com/", policy=policy).host == "xn--pypal-4ve.com"


def test_flags_can_be_toggled_independently() -> None:
    """The two checks catch different attacks, so they must be separately switchable."""
    import dataclasses

    strict = SecurityPolicy.strict()
    assert strict.enforce_mixed_scripts is True
    assert strict.enforce_confusable_host is True

    # Mixed-script off, confusables still on: the homograph passes, the
    # whole-script disguise does not.
    no_mixed = dataclasses.replace(strict, enforce_mixed_scripts=False)
    assert parse_url("http://xn--pypal-4ve.com/", policy=no_mixed).host
    with pytest.raises(urlps.URLpError):
        parse_url("http://xn--80ak6aa92e.com/", policy=no_mixed)

    # And the reverse.
    no_confusable = dataclasses.replace(strict, enforce_confusable_host=False)
    assert parse_url("http://xn--80ak6aa92e.com/", policy=no_confusable).host
    with pytest.raises(urlps.URLpError):
        parse_url("http://xn--pypal-4ve.com/", policy=no_confusable)
