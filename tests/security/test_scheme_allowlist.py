"""Non-standard schemes are opt-in, as ``allow_custom_scheme`` documents.

``parse_url()`` used to accept any syntactically valid scheme that was not on
a short denylist, so an application vetting user-supplied links with it
would happily store ``ms-msdt:`` (Follina), ``search-ms:`` or ``smb://``
links that hand the URL to an OS protocol handler.
"""

from __future__ import annotations

import pytest

from urlps import (
    InvalidURLError,
    UnsupportedSchemeError,
    URLParseError,
    join,
    parse_url,
)

CUSTOM_SCHEME_URLS = [
    "ms-msdt:/id PCWDiagnostic".replace(" ", "%20"),
    "search-ms:query=calc&crumb=location:example",
    "ms-officecmd:x",
    "netdoc:/etc/passwd",
    "livescript:alert(1)",
    "x-javascript:alert(1)",
    "view-source:https://example.com/",
    "mailto:someone@example.com",
    "smb://example.com/share",
    "telnet://example.com/",
    "redis://example.com:6379/",
    "x-custom://example.com/",
    "Ms-Msdt:/id",
]

UNSAFE_SCHEME_URLS = [
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,x",
    "vbscript:x",
    "file:///etc/passwd",
    "gopher://example.com/",
    "dict://example.com:11211/",
    "ldap://example.com/",
    "jar:http://example.com/a.jar!/",
]

STANDARD_URLS = [
    "http://example.com/",
    "HTTPS://example.com/",
    "ftp://example.com/",
    "ftps://example.com/",
    "sftp://example.com/",
    "ws://example.com/",
    "wss://example.com/",
]


@pytest.mark.parametrize("url", CUSTOM_SCHEME_URLS)
def test_non_standard_scheme_is_rejected_by_default(url: str) -> None:
    with pytest.raises(UnsupportedSchemeError, match="allow_custom_scheme"):
        parse_url(url)


@pytest.mark.parametrize("url", CUSTOM_SCHEME_URLS)
def test_non_standard_scheme_is_accepted_when_opted_in(url: str) -> None:
    assert parse_url(url, allow_custom_scheme=True).scheme == url.split(":", 1)[0].lower()


@pytest.mark.parametrize("url", UNSAFE_SCHEME_URLS)
def test_dangerous_scheme_still_requires_opt_in(url: str) -> None:
    with pytest.raises(URLParseError):
        parse_url(url)


@pytest.mark.parametrize("url", STANDARD_URLS)
def test_standard_schemes_are_unaffected(url: str) -> None:
    assert parse_url(url).recognized_scheme is True


@pytest.mark.parametrize(
    "reference",
    ["/redirect?next=http://example.com", "?q=a:b", "page.html#a:b", "//example.com/x", "path/with:colon"],
)
def test_scheme_less_references_are_unaffected(reference: str) -> None:
    assert parse_url(f"https://example.com/{reference.lstrip('/')}").scheme == "https"


@pytest.mark.parametrize("scheme", ["gopher", "file", "javascript", "dict", "ldap", "ms-msdt", "smb", "x-custom"])
def test_with_scheme_cannot_switch_to_a_scheme_parse_url_would_reject(scheme: str) -> None:
    base = parse_url("https://example.com/x")
    with pytest.raises(InvalidURLError):
        base.with_scheme(scheme)


def test_with_scheme_between_standard_schemes_still_works() -> None:
    base = parse_url("https://example.com/x")
    assert base.with_scheme("wss").scheme == "wss"
    assert base.with_scheme("HTTP").scheme is not None


def test_with_scheme_honours_the_urls_own_opt_in() -> None:
    base = parse_url("https://example.com/x", allow_custom_scheme=True)
    assert base.with_scheme("smb").scheme == "smb"


def test_join_cannot_resolve_into_a_non_standard_scheme() -> None:
    with pytest.raises(UnsupportedSchemeError):
        join("https://example.com/a", "ms-msdt:/id")
    assert join("https://example.com/a", "smb://example.com/s", allow_custom_scheme=True).scheme == "smb"
