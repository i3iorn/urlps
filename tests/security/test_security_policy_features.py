import pytest

from src.urlps import (
    SecurityPolicy,
    InvalidURLError,
    build_secure,
    parse_url,
    parse_url_unsafe
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
