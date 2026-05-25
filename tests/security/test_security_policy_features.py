import pytest
from unittest.mock import patch

from urlps import (
    SecurityPolicy,
    InvalidURLError,
    build_secure,
    parse_url,
    parse_url_unsafe
)
from urlps._security.dns_guard import check_dns_rebinding_detailed, DNSRateLimiter
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

    def test_strict_policy_blocks_scheme_relative_credentials(self) -> None:
        with pytest.raises(InvalidURLError):
            parse_url("//user:pass@example.com/path", policy="strict")


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

    def test_validate_honors_explicit_policy_dns_setting(self) -> None:
        u = parse_url_unsafe("http://example.com/")

        with patch(
            "urlps._security.check_dns_rebinding_detailed",
            return_value=(False, ErrorCode.DNS_RESOLUTION_FAILED),
        ):
            findings = u.validate(policy=SecurityPolicy.strict(check_dns=True), raise_on_error=False)

        assert any(f.code == ErrorCode.DNS_RESOLUTION_FAILED.value for f in findings)

    def test_parse_url_passes_injected_dns_limiter(self) -> None:
        limiter = DNSRateLimiter()
        with patch(
            "urlps._security.check_dns_rebinding_detailed",
            return_value=(True, None),
        ) as dns_mock:
            parse_url("http://example.com/", policy="strict", check_dns=True, dns_rate_limiter=limiter)

        assert dns_mock.call_count == 1
        assert dns_mock.call_args.kwargs["limiter"] is limiter

    def test_parse_url_unsafe_passes_injected_dns_limiter(self) -> None:
        limiter = DNSRateLimiter()
        with patch(
            "urlps._security.check_dns_rebinding_detailed",
            return_value=(True, None),
        ) as dns_mock:
            parse_url_unsafe("http://example.com/", check_dns=True, dns_rate_limiter=limiter)

        assert dns_mock.call_count == 1
        assert dns_mock.call_args.kwargs["limiter"] is limiter


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


