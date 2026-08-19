"""
Guards for the checks removed or made opt-in in 1.0.

Two distinct jobs here:

1. Assert the false positives are actually gone -- these are ordinary URLs a
   real application produces, and every one of them was rejected by the 0.8
   default policy.
2. Assert that removing them opened **no bypass**. Every removal was justified
   on the grounds that the dangerous case is still covered by another,
   narrower check; these tests pin that claim down so a future refactor cannot
   quietly invalidate it.
"""

from __future__ import annotations

import pytest

from urlps import InvalidURLError, SecurityPolicy, parse_url
from urlps.exceptions import ErrorCode

# Ordinary URLs that the 0.8 substring blocklist flagged as "query injection".
# "src=", "&&", "--", "$(", backtick and "waitfor" all appear in perfectly
# normal query strings.
LEGITIMATE_QUERIES = [
    "https://shop.example.com/search?q=WAITFOR",
    "https://example.com/?filter=a--b",
    "https://example.com/?cmd=$(x)",
    "https://example.com/?src=homepage",
    "https://example.com/?a=1&&b=2",
    "https://example.com/?q=DROP+TABLE+mountain",
    "https://example.com/?q=union+station",
    "https://example.com/?sql=insert+coin",
    "https://example.com/?tag=alert",
    "https://example.com/?note=%60backtick%60",
    "https://example.com/?path=/bin/bash",
    "https://example.com/?comment=1%3C2",
]


class TestQueryInjectionRemoved:
    @pytest.mark.parametrize("url", LEGITIMATE_QUERIES)
    def test_legitimate_query_parses_under_default_policy(self, url: str) -> None:
        assert parse_url(url).host

    def test_query_injection_flag_no_longer_exists(self) -> None:
        # Passing the removed flag must fail loudly rather than being silently
        # ignored, which would leave callers believing a check is running.
        with pytest.raises(TypeError):
            SecurityPolicy(name="legacy", enforce_query_injection=True)  # type: ignore[call-arg]

    def test_error_code_retained_for_downstream_handlers(self) -> None:
        # Deprecated but importable, so `except ... if e.code is
        # ErrorCode.QUERY_INJECTION` keeps working through the 1.x line.
        assert ErrorCode.QUERY_INJECTION.value == "query_injection"


class TestDangerousPortsNowOptIn:
    @pytest.mark.parametrize("port", [22, 25, 3306, 6379, 11211, 27017])
    def test_public_host_with_notable_port_is_allowed_by_default(self, port: int) -> None:
        assert parse_url(f"http://example.com:{port}/").effective_port == port

    @pytest.mark.parametrize(
        "url",
        [
            "http://10.0.0.1:22/",
            "http://169.254.169.254:3306/",
            "http://127.0.0.1:6379/",
            "http://192.168.1.1:11211/",
            "http://[::1]:27017/",
            "http://2130706433:6379/",  # decimal-encoded 127.0.0.1
        ],
    )
    def test_ssrf_still_blocks_internal_targets_without_port_check(self, url: str) -> None:
        """The whole justification for making port-blocking opt-in."""
        with pytest.raises(InvalidURLError) as exc:
            parse_url(url)
        assert exc.value.code is ErrorCode.SSRF_RISK

    def test_opt_in_still_enforces(self) -> None:
        policy = SecurityPolicy(name="ports", block_dangerous_ports=True)
        with pytest.raises(InvalidURLError) as exc:
            parse_url("http://example.com:22/", policy=policy)
        assert exc.value.code is ErrorCode.DANGEROUS_PORT


class TestCredentialsNowAdvisory:
    def test_credentials_do_not_block_by_default(self) -> None:
        url = parse_url("https://user:pw@example.com/path")
        assert url.host == "example.com"

    def test_credentials_emit_a_non_blocking_warning(self) -> None:
        url = parse_url("https://user:pw@example.com/path")
        creds = [f for f in url.security_findings if f.code == ErrorCode.CREDENTIALS_IN_URL.value]
        assert len(creds) == 1
        assert creds[0].severity == "warning"

    def test_phishing_shape_still_resolves_to_the_real_host(self) -> None:
        """`https://apple.com@evil.com/` must never look like apple.com."""
        for url in (
            "https://apple.com@evil.com/",
            "https://accounts.google.com@evil.com/login",
            "https://www.bank.com:password@evil.com/",
        ):
            assert parse_url(url).host == "evil.com"

    def test_multi_at_smuggling_still_blocked_by_parser_confusion(self) -> None:
        # The credentials flag is off, so this must be caught structurally.
        with pytest.raises(InvalidURLError):
            parse_url("http://foo@evil.com@trusted.com/")

    def test_opt_in_still_enforces(self) -> None:
        policy = SecurityPolicy(name="creds", reject_credentials=True)
        with pytest.raises(InvalidURLError) as exc:
            parse_url("https://user:pw@example.com/", policy=policy)
        assert exc.value.code is ErrorCode.CREDENTIALS_IN_URL


class TestUnrelatedChecksUnaffected:
    """Phase 1 touched the policy defaults; nothing else may have moved."""

    @pytest.mark.parametrize(
        ("url", "code"),
        [
            ("http://169.254.169.254/latest/meta-data/", ErrorCode.SSRF_RISK),
            ("http://127.0.0.1/admin", ErrorCode.SSRF_RISK),
            ("https://example.com/%252e%252e/x", ErrorCode.DOUBLE_ENCODING),
            ("https://example.com/../../etc/passwd", ErrorCode.PATH_TRAVERSAL),
        ],
    )
    def test_still_blocked_under_default_policy(self, url: str, code: ErrorCode) -> None:
        with pytest.raises(InvalidURLError) as exc:
            parse_url(url)
        assert exc.value.code is code
