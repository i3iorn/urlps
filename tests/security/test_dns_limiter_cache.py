"""DNS limiter: cached resolutions, per-tenant isolation, retry_after, deadline.

The process-global limiter used to allow 3 lookups per host per minute and
fail closed, so the 4th legitimate check of a busy host was rejected, three
attacker submissions could lock a host out for a minute, and a burst of junk
hostnames could starve every other caller. A limiter injected on the policy
was also silently replaced by the global one.
"""

from __future__ import annotations

import socket
import time
from unittest.mock import MagicMock, patch

import pytest

from urlps import (
    DNSRateLimiter,
    DNSRateLimiterConfig,
    DNSRateLimiterError,
    DNSRateLimitError,
    ErrorCode,
    InvalidURLError,
    SecurityPolicy,
    parse_url,
)
from urlps._security.dns_guard import check_dns_rebinding_detailed, get_dns_rate_limiter

RESOLVER = "urlps._security.dns_guard._resolve_addr_info"


def _answer(address: str = "93.184.216.34") -> list[tuple]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 80))]


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def test_repeated_checks_of_one_host_all_succeed_with_one_lookup() -> None:
    """Verification from the review: 100 sequential checks of the same public host succeed."""
    with patch(RESOLVER, return_value=_answer()) as resolver:
        for _ in range(100):
            parse_url("https://api.partner.example/webhook", check_dns=True)
    assert resolver.call_count == 1


def test_submitting_a_host_repeatedly_cannot_lock_it_out() -> None:
    with patch(RESOLVER, return_value=_answer()):
        for _ in range(10):  # an attacker submitting the victim's host
            parse_url("https://victim.example/", check_dns=True)
        assert parse_url("https://victim.example/", check_dns=True).host == "victim.example"


def test_one_tenant_cannot_exhaust_another_tenants_limiter() -> None:
    """Verification from the review: tenant isolation through injected limiters."""
    tenant_a = DNSRateLimiter(DNSRateLimiterConfig(max_lookups_per_second=5))
    tenant_b = DNSRateLimiter(DNSRateLimiterConfig(max_lookups_per_second=5))
    with patch(RESOLVER, return_value=_answer()):
        rejected = 0
        for i in range(20):
            try:
                parse_url(f"https://junk{i}.attacker.example/", check_dns=True, dns_rate_limiter=tenant_a)
            except DNSRateLimitError:
                rejected += 1
        assert rejected > 0
        assert parse_url("https://victim.example/", check_dns=True, dns_rate_limiter=tenant_b).host == "victim.example"
    assert get_dns_rate_limiter().stats()["tracked_hosts"] == 0.0


def test_limiter_injected_on_the_policy_is_actually_used() -> None:
    limiter = DNSRateLimiter()
    policy = SecurityPolicy.strict(check_dns=True, dns_rate_limiter=limiter)
    with patch(RESOLVER, return_value=_answer()):
        url = parse_url("https://api.example.com/", policy=policy)
    assert url._security_policy.dns_rate_limiter is limiter
    assert limiter.stats()["cached_hosts"] == 1.0
    assert get_dns_rate_limiter().stats()["cached_hosts"] == 0.0


def test_rate_limit_error_is_retryable_with_retry_after() -> None:
    clock = FakeClock()
    limiter = DNSRateLimiter(
        DNSRateLimiterConfig(max_lookups_per_host=1, time_window_seconds=60, cache_ttl_seconds=0), time_provider=clock
    )
    with patch(RESOLVER, return_value=_answer()):
        parse_url("https://busy.example/", check_dns=True, dns_rate_limiter=limiter)
        clock.now += 15
        with pytest.raises(DNSRateLimitError) as excinfo:
            parse_url("https://busy.example/", check_dns=True, dns_rate_limiter=limiter)
    assert excinfo.value.code is ErrorCode.DNS_RATE_LIMITED
    assert excinfo.value.retry_after == pytest.approx(45.0)
    assert "retry" in excinfo.value.message.lower()


def test_retry_after_reflects_the_global_token_bucket() -> None:
    clock = FakeClock()
    limiter = DNSRateLimiter(DNSRateLimiterConfig(max_lookups_per_second=2), time_provider=clock)
    assert limiter.is_allowed("a.example") and limiter.is_allowed("b.example")
    assert limiter.retry_after("c.example") == pytest.approx(0.5)
    clock.now += 0.5
    assert limiter.retry_after("c.example") == pytest.approx(0.0)


def test_positive_cache_expires_after_its_ttl() -> None:
    clock = FakeClock()
    limiter = DNSRateLimiter(DNSRateLimiterConfig(cache_ttl_seconds=30), time_provider=clock)
    with patch(RESOLVER, return_value=_answer()) as resolver:
        check_dns_rebinding_detailed("cached.example", limiter=limiter)
        clock.now += 29
        check_dns_rebinding_detailed("cached.example", limiter=limiter)
        assert resolver.call_count == 1
        clock.now += 2
        check_dns_rebinding_detailed("cached.example", limiter=limiter)
        assert resolver.call_count == 2


def test_failed_resolution_is_cached_briefly_but_timeouts_are_not() -> None:
    clock = FakeClock()
    limiter = DNSRateLimiter(DNSRateLimiterConfig(negative_cache_ttl_seconds=5), time_provider=clock)
    with patch(RESOLVER, side_effect=socket.gaierror(-2, "unknown")) as resolver:
        assert check_dns_rebinding_detailed("nx.example", limiter=limiter, retries=0) == (
            False,
            ErrorCode.DNS_RESOLUTION_FAILED,
        )
        assert (
            check_dns_rebinding_detailed("nx.example", limiter=limiter, retries=0)[1] is ErrorCode.DNS_RESOLUTION_FAILED
        )
        assert resolver.call_count == 1
        clock.now += 6
        check_dns_rebinding_detailed("nx.example", limiter=limiter, retries=0)
        assert resolver.call_count == 2
    with patch(RESOLVER, side_effect=TimeoutError()) as resolver:
        check_dns_rebinding_detailed("slow.example", limiter=limiter, retries=0)
        check_dns_rebinding_detailed("slow.example", limiter=limiter, retries=0)
        assert resolver.call_count == 2


def test_cached_answer_is_judged_by_each_policy() -> None:
    """The cache holds resolutions, not verdicts."""
    limiter = DNSRateLimiter()
    strict = SecurityPolicy.strict(check_dns=True, dns_rate_limiter=limiter)
    allowing = SecurityPolicy.strict(check_dns=True, dns_rate_limiter=limiter, allowed_addresses=["10.0.0.0/8"])
    with patch(RESOLVER, return_value=_answer("10.1.2.3")) as resolver:
        with pytest.raises(InvalidURLError):
            parse_url("https://build.example/", policy=strict)
        assert parse_url("https://build.example/", policy=allowing).host == "build.example"
        with pytest.raises(InvalidURLError):
            parse_url("https://build.example/", policy=strict)
    assert resolver.call_count == 1


def test_cache_is_bounded() -> None:
    limiter = DNSRateLimiter(DNSRateLimiterConfig(max_cached_hosts=3))
    with patch(RESOLVER, return_value=_answer()):
        for i in range(5):
            check_dns_rebinding_detailed(f"h{i}.example", limiter=limiter)
    assert limiter.stats()["cached_hosts"] == 3.0


def test_zero_ttl_disables_the_cache() -> None:
    limiter = DNSRateLimiter(DNSRateLimiterConfig(cache_ttl_seconds=0))
    with patch(RESOLVER, return_value=_answer()) as resolver:
        check_dns_rebinding_detailed("nocache.example", limiter=limiter)
        check_dns_rebinding_detailed("nocache.example", limiter=limiter)
    assert resolver.call_count == 2


def test_reset_clears_the_cache() -> None:
    limiter = DNSRateLimiter()
    with patch(RESOLVER, return_value=_answer()) as resolver:
        check_dns_rebinding_detailed("r.example", limiter=limiter)
        limiter.reset()
        check_dns_rebinding_detailed("r.example", limiter=limiter)
    assert resolver.call_count == 2


@pytest.mark.parametrize(
    "kwargs",
    [{"cache_ttl_seconds": -1}, {"negative_cache_ttl_seconds": -1}, {"max_cached_hosts": 0}],
)
def test_invalid_cache_config_is_rejected(kwargs: dict) -> None:
    with pytest.raises(DNSRateLimiterError):
        DNSRateLimiterConfig(**kwargs)


def test_deadline_bounds_total_time_across_retries() -> None:
    """A black-holed resolver can no longer hold a thread for timeout x attempts + backoff."""

    def hang(host: str, timeout: float, port: int = 80) -> list:
        time.sleep(timeout)
        raise TimeoutError

    resolver = MagicMock(side_effect=hang)
    started = time.monotonic()
    with patch(RESOLVER, resolver):
        result = check_dns_rebinding_detailed(
            "blackhole.example", timeout_seconds=2.0, retries=5, enforce_rate_limit=False, deadline_seconds=0.3
        )
    elapsed = time.monotonic() - started
    assert result == (False, ErrorCode.DNS_CONNECTION_FAILED)
    assert elapsed < 1.0
    assert resolver.call_args_list[0].args[1] <= 0.3


def test_attempt_timeout_never_exceeds_the_deadline_on_a_coarse_clock() -> None:
    """A frozen clock (as on Windows) must not let float error stretch the first attempt.

    With monotonic() fixed at 1.0, ``(1.0 + 0.3) - 1.0`` is 0.30000000000000004.
    """
    resolver = MagicMock(side_effect=socket.gaierror)
    with patch(RESOLVER, resolver), patch("urlps._security.dns_guard.time.monotonic", return_value=1.0):
        check_dns_rebinding_detailed(
            "coarse-clock.example", timeout_seconds=2.0, retries=0, enforce_rate_limit=False, deadline_seconds=0.3
        )
    assert resolver.call_args_list[0].args[1] <= 0.3


def test_policy_deadline_reaches_the_dns_check() -> None:
    policy = SecurityPolicy(name="custom", check_dns=True, dns_deadline_seconds=1.25)
    with patch("urlps._security.check_dns_rebinding_detailed", return_value=(True, None)) as check:
        parse_url("https://api.example.com/", policy=policy)
    assert check.call_args.kwargs["deadline_seconds"] == 1.25
