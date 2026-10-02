"""Credentials and tokens must not leak through exceptions or audit logs.

Exceptions used to carry the raw URL as ``value`` (and so in ``str(exc)``),
the ``debug`` flag that was meant to gate that was never read, the log
redactor returned the URL unredacted whenever urlsplit() raised, fragments
(OAuth implicit-flow tokens) were never redacted, and only ten exact query
key names were.
"""

from __future__ import annotations

import pytest

from urlps import AuditConfig, InvalidURLError, SecurityPolicy, URLpError, parse_url
from urlps._security import redact_url_for_logs, validate_url_security

SECRETS = ("hunter2", "SECRET", "JWTVALUE")


def _assert_clean(exc: BaseException) -> None:
    rendered = " | ".join([str(exc), repr(exc), repr(getattr(exc, "value", None)), repr(exc.args)])
    for secret in SECRETS:
        assert secret not in rendered, rendered


FAILING_INPUTS = [
    "https://admin:hunter2@127.0.0.1/?token=SECRET",  # SSRF
    "https://admin:hunter2@example.com/a/../b?api_key=SECRET",  # traversal
    "https://admin:hunter2@example.com/?client_secret=SECRET&x=%2541",  # double encoding
    "https://admin:hunter2@[::1/",  # malformed IPv6
    "https://:hunter2@example.com/",  # invalid userinfo
    "https://example.com/?=SECRET",  # query with an empty key
    "https://example.com/#access_token=SECRET<",  # invalid fragment
    "https://admin:hunter2@example.com:99999/",  # bad port
    "mailto:hunter2@example.com",  # unsupported scheme
]


@pytest.mark.parametrize("url", FAILING_INPUTS)
def test_rejection_never_carries_a_secret(url: str) -> None:
    with pytest.raises(URLpError) as excinfo:
        parse_url(url)
    _assert_clean(excinfo.value)


def test_debug_true_keeps_the_raw_value() -> None:
    with pytest.raises(InvalidURLError) as excinfo:
        parse_url("https://admin:hunter2@127.0.0.1/?token=SECRET", debug=True)
    assert "hunter2" in str(excinfo.value)


@pytest.mark.parametrize(
    "derive",
    [
        lambda u: u.with_host("127.0.0.1"),
        lambda u: u.with_query("a=1#SECRET"),
        # A dot-segment path no longer fails: it is normalized like a parse.
        lambda u: u.with_path("//evil.example/x"),
        lambda u: u.validate(policy=SecurityPolicy(name="no-creds", reject_credentials=True), raise_on_error=True),
    ],
)
def test_derivation_failures_never_carry_a_secret(derive) -> None:
    url = parse_url("https://admin:hunter2@example.com/?token=SECRET", policy="balanced")
    with pytest.raises(InvalidURLError) as excinfo:
        derive(url)
    _assert_clean(excinfo.value)


def test_string_api_redacts_by_default() -> None:
    with pytest.raises(InvalidURLError) as excinfo:
        validate_url_security("https://admin:hunter2@127.0.0.1/?token=SECRET")
    _assert_clean(excinfo.value)
    with pytest.raises(InvalidURLError) as excinfo:
        validate_url_security("https://admin:hunter2@127.0.0.1/", debug=True)
    assert "hunter2" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Audit callbacks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [*FAILING_INPUTS, "https://admin:hunter2@exa\uff03mple.com/"])
def test_audit_output_never_carries_a_secret(url: str) -> None:
    logged: list[str] = []
    events: list[dict] = []
    exceptions: list[BaseException] = []

    def callback(logged_url, parsed, exception):
        logged.append(logged_url)
        exceptions.append(exception)

    config = AuditConfig(callback=callback, event_callback=events.append)
    with pytest.raises(URLpError):
        parse_url(url, audit=config)
    for text in [*logged, *(repr(e) for e in events)]:
        for secret in SECRETS:
            assert secret not in text, text
    for exc in exceptions:
        _assert_clean(exc)


def test_audit_extra_sensitive_keys() -> None:
    logged: list[str] = []
    config = AuditConfig(callback=lambda u, p, e: logged.append(u), sensitive_keys=frozenset({"tenant"}))
    parse_url("https://example.com/?tenant_id=acme&page=2", audit=config)
    assert logged == ["https://example.com/?tenant_id=%2A%2A%2A&page=2"]


# ---------------------------------------------------------------------------
# redact_url_for_logs()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["https://admin:hunter2@[::1/", "https://admin:hunter2@exa\uff03mple.com/"],
)
def test_unsplittable_url_is_replaced_not_returned(url: str) -> None:
    assert redact_url_for_logs(url) == "[unparseable URL redacted]"


SENSITIVE_KEYS = [
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "private_token",
    "client_secret",
    "code",
    "sig",
    "X-Amz-Signature",
    "X-Amz-Credential",
    "session",
    "sessionid",
    "SID",
    "key",
    "apiKey",
    "Api-Key",
    "jwt",
    "otp",
    "SAMLResponse",
    "password",
    "passwd",
    "pwd",
    "auth",
    "authorization",
]


@pytest.mark.parametrize("key", SENSITIVE_KEYS)
def test_sensitive_query_keys_are_masked(key: str) -> None:
    redacted = redact_url_for_logs(f"https://example.com/?{key}=SECRET&page=2")
    assert "SECRET" not in redacted
    assert "page=2" in redacted


@pytest.mark.parametrize("key", ["page", "q", "sort", "lang", "utm_source"])
def test_ordinary_query_keys_are_kept(key: str) -> None:
    assert redact_url_for_logs(f"https://example.com/?{key}=visible") == f"https://example.com/?{key}=visible"


def test_fragment_values_are_masked_but_anchors_kept() -> None:
    redacted = redact_url_for_logs("https://app.example/cb#access_token=SECRET&id_token=JWTVALUE&state=xyz")
    assert "SECRET" not in redacted and "JWTVALUE" not in redacted
    assert redact_url_for_logs("https://example.com/doc#section-2") == "https://example.com/doc#section-2"


@pytest.mark.parametrize(
    "url",
    ["user:hunter2@example.com/path", "https:/admin:hunter2@example.com/", "https://admin:hunter2@example.com/"],
)
def test_credentials_are_masked_with_or_without_an_authority(url: str) -> None:
    assert "hunter2" not in redact_url_for_logs(url)


def test_bare_token_userinfo_is_masked() -> None:
    assert redact_url_for_logs("https://ghp_SECRET@github.com/org/repo") == "https://***@github.com/org/repo"


def test_redaction_is_idempotent() -> None:
    once = redact_url_for_logs("https://u:hunter2@example.com/?token=SECRET#access_token=SECRET")
    assert redact_url_for_logs(once) == once


def test_url_redacted_uses_the_same_rules() -> None:
    url = parse_url("https://u:hunter2@example.com/cb?code=SECRET#access_token=SECRET", policy="balanced")
    redacted = url.redacted()
    assert "hunter2" not in redacted and "SECRET" not in redacted
