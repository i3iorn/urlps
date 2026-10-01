"""The host the security checks validate must be the host the URL exposes.

Security validation used to re-extract the host from the raw string with its
own splitter, while ``URL.host`` came from the parser. Wherever the two
disagreed, the checks approved one host and the caller received another:

* the splitter ended the authority only at ``/``, so ``http://127.0.0.1?x``
  was checked as ``127.0.0.1?x`` (not an IP, so not an SSRF risk) while the
  parser produced ``127.0.0.1``;
* the parser applies UTS-46 mapping and the splitter did not, so
  ``http://127\\u30020\\u30020\\u30021/`` (ideographic full stops) and
  fullwidth ``localhost`` passed the checks and parsed to loopback.

Non-ASCII characters are written as escapes so the hosts under test are
reviewable in source.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from urlps import (
    InvalidURLError,
    PortValidationError,
    SecurityPolicy,
    build_secure,
    join,
    parse_url,
    parse_url_local,
)
from urlps._security import collect_security_findings, extract_host_and_path

IDEOGRAPHIC_FULL_STOP = "。"
FULLWIDTH_FULL_STOP = "．"
HALFWIDTH_IDEOGRAPHIC_FULL_STOP = "｡"
FULLWIDTH_127_0_0_1 = "１２７。０。０。１"
FULLWIDTH_LOCALHOST = "ｌｏｃａｌｈｏｓｔ"


def _ssrf_code(url: str) -> str | None:
    with pytest.raises(InvalidURLError) as excinfo:
        parse_url(url)
    code = excinfo.value.code
    return code.value if code is not None else None


# ---------------------------------------------------------------------------
# Delimiter directly after the host
# ---------------------------------------------------------------------------

DELIMITER_BYPASSES = [
    "http://127.0.0.1?x",
    "http://127.0.0.1#x",
    "http://127.0.0.1?",
    "http://127.0.0.1#",
    "http://169.254.169.254?",
    "http://169.254.169.254#",
    "http://localhost?x",
    "http://metadata.google.internal?x",
    "http://[::1]?x",
    "http://[fe80::1%25eth0]?x",
    "http://user@127.0.0.1?x",
    "http://127.0.0.1:8080?x",
    "//127.0.0.1?x",
]


@pytest.mark.parametrize("url", DELIMITER_BYPASSES)
def test_query_or_fragment_right_after_host_is_still_ssrf_checked(url: str) -> None:
    assert _ssrf_code(url) == "ssrf_risk"


@pytest.mark.parametrize(
    "url",
    ["http://169.254.169.254?", "http://169.254.169.254#x", "http://metadata.google.internal?x"],
)
def test_local_policy_still_blocks_metadata_behind_a_delimiter(url: str) -> None:
    """parse_url_local() promises metadata endpoints stay blocked."""
    with pytest.raises(InvalidURLError) as excinfo:
        parse_url_local(url)
    assert excinfo.value.code is not None
    assert excinfo.value.code.value == "ssrf_risk"


@pytest.mark.parametrize("url", ["https://example.com?x=1", "https://example.com#frag", "https://example.com?"])
def test_public_host_followed_by_delimiter_still_parses(url: str) -> None:
    assert parse_url(url).host == "example.com"


# ---------------------------------------------------------------------------
# Hosts that only become dangerous after UTS-46 mapping
# ---------------------------------------------------------------------------

MAPPED_BYPASSES = [
    f"http://127{IDEOGRAPHIC_FULL_STOP}0{IDEOGRAPHIC_FULL_STOP}0{IDEOGRAPHIC_FULL_STOP}1/",
    f"http://{FULLWIDTH_127_0_0_1}/",
    f"http://{FULLWIDTH_LOCALHOST}/",
    f"http://169{FULLWIDTH_FULL_STOP}254{FULLWIDTH_FULL_STOP}169{FULLWIDTH_FULL_STOP}254/",
    f"http://169{HALFWIDTH_IDEOGRAPHIC_FULL_STOP}254{HALFWIDTH_IDEOGRAPHIC_FULL_STOP}169"
    f"{HALFWIDTH_IDEOGRAPHIC_FULL_STOP}254/",
    f"http://metadata{IDEOGRAPHIC_FULL_STOP}google{IDEOGRAPHIC_FULL_STOP}internal/",
]


@pytest.mark.parametrize("url", MAPPED_BYPASSES)
def test_idna_mapped_spelling_of_internal_host_is_rejected(url: str) -> None:
    assert _ssrf_code(url) == "ssrf_risk"


@pytest.mark.parametrize("url", MAPPED_BYPASSES)
def test_idna_mapped_spelling_is_rejected_by_string_api_too(url: str) -> None:
    """collect_security_findings() without parsed components canonicalizes the host itself."""
    codes = {f.code for f in collect_security_findings(url, policy="strict")}
    assert "ssrf_risk" in codes


def test_string_api_still_checks_a_host_idna_rejects() -> None:
    """A host IDNA refuses is analysed as written rather than skipped."""
    codes = {f.code for f in collect_security_findings("http://\u202eexample.com/", policy="strict")}
    assert "bidi_control_in_host" in codes


def test_legitimate_idn_still_parses() -> None:
    url = parse_url("https://münchen.de/")
    assert url.host == "xn--mnchen-3ya.de"


# ---------------------------------------------------------------------------
# Every entry point, not just parse_url()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reference",
    ["//127.0.0.1?x", "http://169.254.169.254#", f"//127{IDEOGRAPHIC_FULL_STOP}0{IDEOGRAPHIC_FULL_STOP}0.1/"],
)
def test_join_rejects_differential_targets(reference: str) -> None:
    with pytest.raises(InvalidURLError):
        join("https://example.com/a", reference)


def test_build_secure_rejects_idna_mapped_internal_host() -> None:
    with pytest.raises(InvalidURLError):
        build_secure("http", f"127{IDEOGRAPHIC_FULL_STOP}0{IDEOGRAPHIC_FULL_STOP}0{IDEOGRAPHIC_FULL_STOP}1")


@pytest.mark.parametrize(
    "host",
    [FULLWIDTH_127_0_0_1, FULLWIDTH_LOCALHOST, f"169{IDEOGRAPHIC_FULL_STOP}254{IDEOGRAPHIC_FULL_STOP}169.254"],
)
def test_with_host_rejects_idna_mapped_internal_host(host: str) -> None:
    base = parse_url("https://example.com/")
    with pytest.raises(InvalidURLError):
        base.with_host(host)


def test_with_host_stores_the_ascii_form() -> None:
    """copy() must IDNA-encode like the parser, so .host is always ASCII."""
    fullwidth_example = "ｅｘａｍｐｌｅ.com"
    url = parse_url("https://other.com/").with_host(fullwidth_example)
    assert url.host == "example.com"
    assert url.host == parse_url(f"https://{fullwidth_example}/").host

    idn = parse_url("https://other.com/").with_host("münchen.de")
    assert idn.host == "xn--mnchen-3ya.de"


@pytest.mark.parametrize("policy", ["strict", "internal", "local"])
@pytest.mark.parametrize("userinfo", ["169.254.169.254#", "169.254.169.254?", "169.254.169.254/", "169.254.169.254\\"])
def test_userinfo_override_cannot_smuggle_a_metadata_authority(policy: str, userinfo: str) -> None:
    """str(url) must name the same host as url.host for every parser.

    The userinfo is percent-encoded to the RFC 3986 grammar, so the
    authority-ending character cannot reach the serialized URL raw.
    """
    from urllib.parse import urlsplit

    base = parse_url("http://example.com/", policy=policy)
    for derived in (lambda: base.with_userinfo(userinfo), lambda: base.with_netloc(f"{userinfo}@example.com")):
        try:
            url = derived()
        except InvalidURLError:
            continue
        assert url.host == "example.com"
        assert urlsplit(str(url)).hostname == "example.com"
        authority = str(url).split("://", 1)[1].split("/", 1)[0]
        assert not any(char in authority for char in "#?\\")


# ---------------------------------------------------------------------------
# DNS and phishing checks see the authoritative host
# ---------------------------------------------------------------------------


def test_dns_check_resolves_the_host_the_url_exposes() -> None:
    """Not the raw spelling: getaddrinfo would IDNA-2003-encode it (faß.de -> fass.de)."""
    with patch("urlps._security.check_dns_rebinding_detailed", return_value=(True, None)) as dns_check:
        url = parse_url("https://faß.de/", check_dns=True)
    dns_check.assert_called_once()
    assert dns_check.call_args.args[0] == url.host
    assert url.host.isascii()


def test_dns_check_sees_host_without_trailing_query() -> None:
    with patch("urlps._security.check_dns_rebinding_detailed", return_value=(True, None)) as dns_check:
        parse_url("https://api.example.com?x=1", check_dns=True)
    assert dns_check.call_args.args[0] == "api.example.com"


@pytest.mark.parametrize(
    "url",
    ["https://phish.example?x", "https://phish.example#x", "https://PHISH.example./", "https://phish.example/"],
)
def test_phishing_check_matches_every_spelling(url: str) -> None:
    with patch(
        "urlps._security.check_against_phishing_db_detailed",
        side_effect=lambda host: (host == "phish.example", True),
    ):
        with pytest.raises(InvalidURLError) as excinfo:
            parse_url(url, check_phishing=True)
    assert excinfo.value.code is not None
    assert excinfo.value.code.value == "phishing_domain"


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("port", ["２２", "٢٢", "٦٣٧٩"])
def test_non_ascii_digits_are_not_a_port(port: str) -> None:
    """int() reads "２２" as 22 while urlsplit() rejects it -- one port, two meanings."""
    with pytest.raises(PortValidationError):
        parse_url(f"http://example.com:{port}/", policy="balanced")


def test_dangerous_port_check_uses_the_port_the_url_connects_to() -> None:
    """sftp://host/ and sftp://host:22/ are the same URL (port 22) and get the same verdict."""
    policy = SecurityPolicy(name="ports", block_dangerous_ports=True)
    for url in ("sftp://example.com/", "sftp://example.com:22/"):
        with pytest.raises(InvalidURLError) as excinfo:
            parse_url(url, policy=policy)
        assert excinfo.value.code is not None
        assert excinfo.value.code.value == "dangerous_port"
    assert parse_url("https://example.com/", policy=policy).port == 443


# ---------------------------------------------------------------------------
# The raw-string splitter itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://127.0.0.1?x", ("127.0.0.1", "")),
        ("http://127.0.0.1#x", ("127.0.0.1", "")),
        ("http://user@[::1]:8080?x", ("[::1]", "")),
        ("http://example.com/a/b?c=/d#/e", ("example.com", "/a/b")),
        ("http://example.com?next=/a/../b", ("example.com", "")),
    ],
)
def test_extract_host_and_path_ends_authority_at_query_and_fragment(url: str, expected: tuple[str, str]) -> None:
    assert extract_host_and_path(url) == expected
