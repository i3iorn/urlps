import pytest

from urlps import (
    SecurityPolicy,
    InvalidURLError,
    build_secure,
    parse_url,
    parse_url_unsafe,
    set_audit_callback,
    set_audit_event_callback,
)


class TestSecurityPolicy:
    def test_non_canonical_blocked_in_strict_policy(self) -> None:
        with pytest.raises(InvalidURLError):
            parse_url("HTTP://example.com/", policy="strict")

    def test_balanced_policy_allows_non_canonical(self) -> None:
        url = parse_url("HTTP://example.com/", policy="balanced")
        assert url.scheme == "http"

    def test_query_injection_blocked_in_strict_policy(self) -> None:
        with pytest.raises(InvalidURLError):
            parse_url("http://example.com/?x=<script>alert(1)</script>", policy="strict")

    def test_dangerous_port_blocked_in_strict_policy(self) -> None:
        with pytest.raises(InvalidURLError):
            parse_url("http://example.com:22/", policy="strict")

    def test_copy_rechecks_security(self) -> None:
        u = parse_url("http://example.com/", policy="strict")
        with pytest.raises(InvalidURLError):
            u.with_host("127.0.0.1")


class TestSecurityAPIs:
    def test_validate_returns_findings(self) -> None:
        u = parse_url_unsafe("http://example.com/?x=<script>alert(1)</script>")
        findings = u.validate(policy=SecurityPolicy.strict())
        assert findings
        assert any(f.code == "query_injection" for f in findings)

    def test_redacted_masks_sensitive_data(self) -> None:
        u = parse_url_unsafe("http://user:pass@example.com/?token=abc&x=1")
        redacted = u.redacted()
        assert "pass" not in redacted
        assert "abc" not in redacted
        assert "token=%2A%2A%2A" in redacted


class TestSecureBuilder:
    def test_build_secure_validates(self) -> None:
        with pytest.raises(InvalidURLError):
            build_secure("http", "example.com", port=22, policy="strict")


class TestStructuredAudit:
    def teardown_method(self) -> None:
        set_audit_callback(None)
        set_audit_event_callback(None)

    def test_audit_callback_receives_redacted_url(self) -> None:
        called = {}

        def callback(raw_url, parsed_url, exception):
            called["raw_url"] = raw_url

        set_audit_callback(callback)
        parse_url_unsafe("http://user:pass@example.com/?token=abc")
        assert "pass" not in called["raw_url"]
        assert "abc" not in called["raw_url"]

    def test_structured_event_callback(self) -> None:
        events = []

        def event_callback(event):
            events.append(event)

        set_audit_event_callback(event_callback)
        parse_url("http://example.com/", policy="balanced", correlation_id="req-1")
        assert len(events) == 1
        assert events[0]["operation"] == "url_parse"
        assert events[0]["correlation_id"] == "req-1"

