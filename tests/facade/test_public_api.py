"""Public API surface, audit wiring, and mutation-path validation.

Covers the 0.7.0 API-honesty work:

* Types users need are importable from ``urlps`` rather than private modules.
* The audit types are actually reachable (they were exported but unusable).
* ``copy()`` validates components as strictly as ``parse_url`` does.
* The redundant ``strict`` parameter is gone.
"""

import pytest

import urlps
from urlps import (
    URL,
    AuditConfig,
    DNSRateLimiter,
    DNSRateLimiterConfig,
    ErrorCode,
    InvalidURLError,
    SecurityFinding,
    parse_url,
    parse_url_unsafe,
)


class TestPublicExports:
    """Everything a user needs must be importable from the package root."""

    @pytest.mark.parametrize(
        "name",
        [
            "URL",
            "AuditCallback",
            "AuditConfig",
            "AuditEventCallback",
            "AuditManager",
            "DNSRateLimiter",
            "DNSRateLimiterConfig",
            "ErrorCode",
            "SecurityFinding",
            "SecurityPolicy",
            "PolicyInput",
            "InvalidURLError",
            "URLParseError",
            "URLBuildError",
            "URLpError",
            "HostValidationError",
            "PortValidationError",
            "QueryParsingError",
            "UnsupportedSchemeError",
            "build",
            "build_secure",
            "compose_url",
            "join",
            "parse_url",
            "parse_url_unsafe",
        ],
    )
    def test_name_is_exported(self, name):
        assert name in urlps.__all__, f"{name} missing from __all__"
        assert hasattr(urlps, name), f"{name} not importable from urlps"

    def test_dns_rate_limiter_needs_no_private_import(self):
        """DNSRateLimiter must be importable from the package root, not a private module."""
        limiter = DNSRateLimiter(DNSRateLimiterConfig(max_lookups_per_second=5))
        assert limiter.is_allowed("example.com") is True

    def test_security_finding_type_is_public(self):
        """URL.security_findings returns these, so the type must be reachable."""
        url = parse_url("https://example.com/")
        assert isinstance(url.security_findings, list)
        assert SecurityFinding is not None

    def test_error_code_is_public(self):
        """Exceptions carry .code; switching on it requires the enum."""
        with pytest.raises(InvalidURLError) as exc_info:
            parse_url("http://localhost/admin")
        assert exc_info.value.code == ErrorCode.SSRF_RISK

    def test_documented_readme_names_do_not_lie(self):
        """The README documented set_audit_callback/set_audit_event_callback.

        Neither ever existed. Guard against the docs drifting back.
        """
        assert not hasattr(urlps, "set_audit_callback")
        assert not hasattr(urlps, "set_audit_event_callback")


class TestAuditIsReachable:
    """AuditManager/AuditConfig were exported but could not be attached."""

    def test_simple_callback_fires_on_success(self):
        seen = []

        def callback(logged_url, parsed_url, exception):
            seen.append((logged_url, parsed_url, exception))

        parse_url("https://example.com/path", audit=AuditConfig(callback=callback))
        assert len(seen) == 1
        _logged_url, parsed_url, exception = seen[0]
        assert exception is None
        assert parsed_url is not None
        assert parsed_url.host == "example.com"

    def test_simple_callback_fires_on_failure(self):
        seen = []

        def callback(logged_url, parsed_url, exception):
            seen.append(exception)

        with pytest.raises(InvalidURLError):
            parse_url("http://localhost/admin", audit=AuditConfig(callback=callback))
        assert len(seen) == 1
        assert isinstance(seen[0], InvalidURLError)

    def test_event_callback_receives_structured_event(self):
        events = []
        config = AuditConfig(event_callback=events.append)

        parse_url("https://example.com/p", correlation_id="req-1", audit=config)

        assert len(events) == 1
        event = events[0]
        for key in ("timestamp", "level", "operation", "raw_url", "host", "correlation_id"):
            assert key in event
        assert event["host"] == "example.com"
        assert event["correlation_id"] == "req-1"
        assert event["level"] == "info"

    def test_event_callback_reports_error_code_on_failure(self):
        events = []
        with pytest.raises(InvalidURLError):
            parse_url(
                "http://localhost/admin",
                audit=AuditConfig(event_callback=events.append),
            )
        assert events[0]["level"] == "error"
        assert events[0]["error_code"] == ErrorCode.SSRF_RISK.value

    def test_credentials_are_redacted_by_default(self):
        seen = []
        parse_url_unsafe(
            "https://user:hunter2@example.com/",
            audit=AuditConfig(callback=lambda u, p, e: seen.append(u)),
        )
        assert "hunter2" not in seen[0]

    def test_callback_exception_does_not_break_parsing(self):
        def exploding(logged_url, parsed_url, exception):
            raise RuntimeError("audit sink is down")

        url = parse_url("https://example.com/", audit=AuditConfig(callback=exploding))
        assert url.host == "example.com"

    def test_audit_works_through_parse_url_unsafe_and_join(self):
        events = []
        config = AuditConfig(event_callback=events.append)
        parse_url_unsafe("http://localhost:3000/", audit=config)
        urlps.join("https://example.com/a/b", "../c", audit=config)
        assert len(events) == 2

    def test_audit_must_be_an_audit_config(self):
        with pytest.raises(TypeError, match="AuditConfig"):
            parse_url("https://example.com/", audit={"callback": None})  # type: ignore[arg-type]


class TestStrictParameterRemoved:
    """`strict` was redundant with `policy` and silently ignored alongside it."""

    def test_parse_url_unsafe_rejects_strict(self):
        with pytest.raises(TypeError, match="unexpected keyword argument"):
            parse_url_unsafe("https://example.com/", strict=True)  # type: ignore[call-arg]

    def test_url_constructor_rejects_strict(self):
        with pytest.raises(TypeError, match="unexpected keyword argument"):
            URL("https://example.com/", strict=True)  # type: ignore[call-arg]

    def test_policy_is_the_single_control(self):
        assert parse_url_unsafe("http://localhost:3000/").host == "localhost"
        with pytest.raises(InvalidURLError):
            parse_url_unsafe("http://localhost:3000/", policy="strict")


class TestCopyValidatesComponents:
    """copy()/with_* must validate overrides, not just type-check them."""

    @pytest.mark.parametrize(
        "host",
        ["not a valid host!", "exa mple.com", "bad_host!.com", "-leading-hyphen.com"],
    )
    def test_invalid_host_is_rejected(self, host):
        url = parse_url("https://example.com/a")
        with pytest.raises(InvalidURLError):
            url.with_host(host)

    @pytest.mark.parametrize("host", ["other.example.com", "8.8.8.8"])
    def test_valid_host_is_accepted(self, host):
        url = parse_url("https://example.com/a")
        assert url.with_host(host).host == host

    def test_ip_literals_are_valid_hosts_but_still_policy_checked(self):
        """Format validity and policy are separate concerns."""
        internal = parse_url_unsafe("http://internal.example/a")
        assert internal.with_host("192.168.0.1").host == "192.168.0.1"
        assert internal.with_host("[::1]").host == "[::1]"

        public = parse_url("https://example.com/a")
        with pytest.raises(InvalidURLError):
            public.with_host("192.168.0.1")  # blocked by SSRF policy

    def test_invalid_scheme_is_rejected(self):
        url = parse_url("https://example.com/a")
        with pytest.raises(InvalidURLError):
            url.with_scheme("1bad")

    def test_invalid_scheme_type_is_rejected(self):
        url = parse_url("https://example.com/a")
        with pytest.raises(InvalidURLError):
            url.with_scheme(123)  # type: ignore[arg-type]

    def test_with_scheme_none_clears_it(self):
        """`None` clears the scheme, matching with_host/with_query/with_fragment."""
        url = parse_url("https://example.com/a")
        assert url.with_scheme(None).scheme is None

    def test_control_characters_rejected_in_path_and_query(self):
        url = parse_url("https://example.com/a")
        with pytest.raises(InvalidURLError):
            url.with_path("/bad\npath")
        with pytest.raises(InvalidURLError):
            url.with_query("a=b\x00c")

    def test_unknown_override_key_is_rejected(self):
        url = parse_url("https://example.com/a")
        with pytest.raises(InvalidURLError, match="Invalid override"):
            url.copy(nonexistent="x")

    def test_copy_matches_parse_url_strictness(self):
        """A host copy() accepts must also be one parse_url would accept."""
        bad = "not a valid host!"
        with pytest.raises(InvalidURLError):
            parse_url(f"https://{bad}/a")
        with pytest.raises(InvalidURLError):
            parse_url("https://example.com/a").with_host(bad)
