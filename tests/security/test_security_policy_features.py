import socket
from unittest.mock import patch

import pytest

from urlps import InvalidURLError, SecurityPolicy, build_secure, parse_url, parse_url_unsafe
from urlps._security.dns_guard import DNSRateLimiter, check_dns_rebinding_detailed
from urlps.exceptions import ErrorCode


class TestSecurityPolicy:
    @pytest.mark.parametrize("policy", ["strict", "balanced", "internal"])
    def test_non_canonical_is_normalized_not_rejected(self, policy: str) -> None:
        # 1.0 normalizes rather than gating: canonical form is an invariant of
        # every URL object, so no policy can switch it off.
        url = parse_url("HTTP://EXAMPLE.COM.:80/a/./b", policy=policy)
        assert url.scheme == "http"
        assert url.host == "example.com"
        assert str(url) == "http://example.com/a/b"

    def test_dangerous_port_is_opt_in(self) -> None:
        # Not blocked by default: SSRF-to-internal-service is already covered
        # by enforce_ssrf, and a blocked port on a *public* host is deployment
        # policy rather than a property of the URL.
        assert parse_url("http://example.com:22/", policy="strict").effective_port == 22

        policy = SecurityPolicy(name="ports", block_dangerous_ports=True)
        with pytest.raises(InvalidURLError):
            parse_url("http://example.com:22/", policy=policy)

    def test_copy_rechecks_security(self) -> None:
        u = parse_url("http://example.com/", policy="strict")
        with pytest.raises(InvalidURLError):
            u.with_host("127.0.0.1")

    def test_scheme_relative_credentials_are_opt_in(self) -> None:
        assert parse_url("//user:pass@example.com/path", policy="strict").host == "example.com"

        policy = SecurityPolicy(name="creds", reject_credentials=True)
        with pytest.raises(InvalidURLError):
            parse_url("//user:pass@example.com/path", policy=policy)


class TestSecurityAPIs:
    def test_validate_returns_findings(self) -> None:
        # Parsed under the permissive internal policy, then re-validated under
        # strict. Uses an SSRF host rather than a traversal path because the
        # parser resolves dot segments, so "/a/../b" is already normalized
        # away by the time validate() sees the stored URL.
        u = parse_url_unsafe(
            "http://169.254.169.254/latest/meta-data/",
            policy=SecurityPolicy.internal(enforce_ssrf=False),
        )
        findings = u.validate(policy=SecurityPolicy.strict(), raise_on_error=False)
        assert findings
        assert any(f.code == ErrorCode.SSRF_RISK.value for f in findings)

    def test_redacted_masks_sensitive_data(self) -> None:
        u = parse_url_unsafe("http://user:pass@example.com/?token=abc&x=1")
        redacted = u.redacted()
        assert "pass" not in redacted
        assert "abc" not in redacted
        assert "token=%2A%2A%2A" in redacted

    def test_validate_honors_explicit_policy_dns_setting(self, fakes) -> None:
        resolver = fakes.Resolver(error=socket.gaierror(-2, "unknown"))
        u = parse_url_unsafe("http://example.com/", services=fakes.services(resolver=resolver))

        findings = u.validate(policy=SecurityPolicy.strict(check_dns=True), raise_on_error=False)

        assert any(f.code == ErrorCode.DNS_RESOLUTION_FAILED.value for f in findings)

    def test_parse_url_passes_injected_dns_limiter(self, fakes) -> None:
        limiter = DNSRateLimiter()
        parse_url(
            "http://example.com/", policy="strict", check_dns=True, dns_rate_limiter=limiter, services=fakes.services()
        )
        assert limiter.stats()["tracked_hosts"] == 1.0

    def test_parse_url_unsafe_passes_injected_dns_limiter(self, fakes) -> None:
        limiter = DNSRateLimiter()
        parse_url_unsafe("http://example.com/", check_dns=True, dns_rate_limiter=limiter, services=fakes.services())
        assert limiter.stats()["tracked_hosts"] == 1.0


class TestSecureBuilder:
    def test_build_secure_validates(self) -> None:
        with pytest.raises(InvalidURLError):
            build_secure("http", "169.254.169.254", path="/latest/meta-data/", policy="strict")


class TestDnsConnectPolicyBehavior:
    def test_strict_policy_defaults_to_fail_closed(self) -> None:
        policy = SecurityPolicy.strict(check_dns=True)
        assert policy.dns_fail_open_on_connect_error is False

    def test_balanced_policy_defaults_to_fail_open(self) -> None:
        policy = SecurityPolicy.balanced(check_dns=True)
        assert policy.dns_fail_open_on_connect_error is True

    def test_dns_check_makes_no_connection(self) -> None:
        """The verification connect is gone: it re-checked the address just
        resolved, so it could not detect rebinding, and only added an outbound
        connection to an attacker-chosen host."""
        fake_addrinfo = [(2, 1, 6, "", ("93.184.216.34", 80))]
        with (
            patch("urlps._security.dns_guard._resolve_addr_info", return_value=fake_addrinfo),
            patch("socket.socket", side_effect=AssertionError("check_dns must not open a socket")),
        ):
            for fail_open in (True, False):
                is_safe, error = check_dns_rebinding_detailed(
                    host="example.com",
                    enforce_rate_limit=False,
                    fail_open_on_connect_error=fail_open,
                )
                assert is_safe is True
                assert error is None

    def test_passing_the_fail_open_flag_to_a_preset_is_deprecated(self) -> None:
        with pytest.warns(DeprecationWarning, match="dns_fail_open_on_connect_error"):
            SecurityPolicy.strict(dns_fail_open_on_connect_error=True)
