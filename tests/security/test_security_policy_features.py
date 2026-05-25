import pytest
from unittest.mock import patch

from urlps import (
    SecurityPolicy,
    InvalidURLError,
    build_secure,
    parse_url,
    parse_url_unsafe
)
from urlps._security.dns_guard import check_dns_rebinding_detailed
from urlps.exceptions import ErrorCode


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


class TestDnsConnectPolicyBehavior:
    def test_strict_policy_defaults_to_fail_closed(self) -> None:
        policy = SecurityPolicy.strict(check_dns=True)
        assert policy.dns_fail_open_on_connect_error is False

    def test_balanced_policy_defaults_to_fail_open(self) -> None:
        policy = SecurityPolicy.balanced(check_dns=True)
        assert policy.dns_fail_open_on_connect_error is True

    def test_dns_connect_can_fail_open_when_configured(self) -> None:
        fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 80))]
        with patch("urlps._security.dns_guard._resolve_addr_info", return_value=fake_addrinfo), patch(
            "urlps._security.dns_guard._check_resolved_ips_safe", return_value=True
        ), patch(
            "urlps._security.dns_guard._verify_connection_safe",
            side_effect=lambda *args, **kwargs: kwargs.get("fail_open_on_error", False),
        ):
            is_safe, error = check_dns_rebinding_detailed(
                host="example.com",
                enforce_rate_limit=False,
                fail_open_on_connect_error=True,
            )

        assert is_safe is True
        assert error is None

    def test_dns_connect_fails_closed_when_configured(self) -> None:
        fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 80))]
        with patch("urlps._security.dns_guard._resolve_addr_info", return_value=fake_addrinfo), patch(
            "urlps._security.dns_guard._check_resolved_ips_safe", return_value=True
        ), patch(
            "urlps._security.dns_guard._verify_connection_safe",
            side_effect=lambda *args, **kwargs: kwargs.get("fail_open_on_error", False),
        ):
            is_safe, error = check_dns_rebinding_detailed(
                host="example.com",
                enforce_rate_limit=False,
                fail_open_on_connect_error=False,
            )

        assert is_safe is False
        assert error == ErrorCode.DNS_CONNECTION_FAILED


