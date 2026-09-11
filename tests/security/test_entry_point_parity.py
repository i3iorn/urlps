"""Every entry point must agree on what it enforces.

This module pins the matrix so that divergence cannot come back. Anything that
takes an untrusted URL and hands back a validated ``URL`` enforces the default
policy; the two documented string builders do not, and that is asserted here
rather than left implicit.
"""

from __future__ import annotations

import pytest

import urlps
from urlps import SecurityPolicy

#: Hosts that must be rejected by every validating entry point. Spellings are
#: deliberately varied -- plain, obfuscated decimal, and IPv4-mapped IPv6 --
#: so a regression in any one normalization path shows up here.
HOSTILE_URLS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://2130706433/",
    "http://[::ffff:127.0.0.1]/",
    "http://metadata.google.internal/",
]


def _raises(fn) -> bool:
    try:
        fn()
    except urlps.URLpError:
        return True
    return False


# ---------------------------------------------------------------------------
# Validating entry points
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", HOSTILE_URLS)
def test_parse_url_enforces(url: str) -> None:
    assert _raises(lambda: urlps.parse_url(url))


@pytest.mark.parametrize("url", HOSTILE_URLS)
def test_url_constructor_enforces(url: str) -> None:
    """The regression this module exists for: URL() must match parse_url()."""
    assert _raises(lambda: urlps.URL(url))


@pytest.mark.parametrize("url", HOSTILE_URLS)
def test_url_constructor_and_parse_url_agree(url: str) -> None:
    assert _raises(lambda: urlps.URL(url)) == _raises(lambda: urlps.parse_url(url))


@pytest.mark.parametrize("url", HOSTILE_URLS)
def test_join_enforces(url: str) -> None:
    assert _raises(lambda: urlps.join("https://example.com/", url))


@pytest.mark.parametrize("url", HOSTILE_URLS)
def test_build_secure_enforces(url: str) -> None:
    host = urlps.parse_url(url, policy=SecurityPolicy.internal(enforce_ssrf=False)).host
    assert _raises(lambda: urlps.build_secure("http", host))


@pytest.mark.parametrize(
    "method, argument",
    [
        ("with_host", "169.254.169.254"),
        ("with_host", "127.0.0.1"),
        ("with_netloc", "10.0.0.1:8080"),
    ],
)
def test_mutation_methods_revalidate(method: str, argument: str) -> None:
    """A validated URL must not become invalid by deriving a new one from it."""
    url = urlps.parse_url("https://example.com/")
    assert _raises(lambda: getattr(url, method)(argument))


def test_copy_revalidates() -> None:
    url = urlps.parse_url("https://example.com/")
    assert _raises(lambda: url.copy(host="169.254.169.254"))


# ---------------------------------------------------------------------------
# Non-validating entry points -- documented, and asserted so it stays deliberate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("builder", ["build", "compose_url"])
def test_string_builders_do_not_validate(builder: str) -> None:
    """``build``/``compose_url`` compose strings; ``build_secure`` is the checked variant.

    Asserted rather than assumed: if either ever starts validating, that is a
    behaviour change that should be a deliberate edit to this test.
    """
    if builder == "build":
        assert urlps.build("http", "169.254.169.254") == "http://169.254.169.254/"
    else:
        composed = urlps.compose_url({"scheme": "http", "host": "169.254.169.254", "path": "/"})
        assert "169.254.169.254" in composed


# ---------------------------------------------------------------------------
# The local escape hatch is narrow, not a blanket opt-out
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:3000/api",
        "http://127.0.0.1:8080/",
        "http://192.168.1.50/metrics",
        "http://10.0.0.5/",
        "http://[::1]:9000/",
        "http://172.16.0.1/",
    ],
)
def test_parse_url_local_allows_development_hosts(url: str) -> None:
    assert urlps.parse_url_local(url).host


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://metadata.goog/",
        "http://169.254.170.2/v2/credentials/",
        "http://kubernetes.default.svc/",
        "http://internal.corp.internal/",
        "http://[fe80::1]/",
        "http://0.0.0.0/",  # nosec B104 -- asserting this is blocked, not binding
    ],
)
def test_parse_url_local_still_blocks_metadata_and_link_local(url: str) -> None:
    """``local`` narrows SSRF enforcement; it does not switch it off."""
    assert _raises(lambda: urlps.parse_url_local(url))


def test_parse_url_unsafe_is_a_deprecated_alias_for_parse_url_local() -> None:
    """parse_url_unsafe() delegates to parse_url_local() and warns.

    They're no longer the same function object (that's what lets the
    deprecation warning attach only to the old name), but behavior for
    identical arguments must still match exactly.
    """
    import warnings

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        unsafe_result = urlps.parse_url_unsafe("http://localhost:3000/api")

    assert any(issubclass(w.category, DeprecationWarning) for w in caught)

    local_result = urlps.parse_url_local("http://localhost:3000/api")
    assert unsafe_result.as_string() == local_result.as_string()


def test_disabling_ssrf_requires_saying_so() -> None:
    """The only way to permit a metadata endpoint is an explicit opt-out."""
    url = "http://169.254.169.254/"
    assert _raises(lambda: urlps.parse_url(url, policy="internal"))
    assert _raises(lambda: urlps.parse_url(url, policy="local"))
    assert urlps.parse_url(url, policy=SecurityPolicy.internal(enforce_ssrf=False)).host
