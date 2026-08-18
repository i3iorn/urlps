"""Robustness: SSRF bypasses, fail-closed behaviour, and thread safety.

Covers the 0.7.0 hardening work:

* Obfuscated IPv4 forms that bypassed SSRF checks entirely.
* Checks that could not reach a verdict now fail closed rather than open.
* ``check_phishing=True`` no longer silently degrades to no protection.
* Shared mutable state is synchronised (the project's first concurrency tests).
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest

from urlps import DNSRateLimiter, DNSRateLimiterConfig, InvalidURLError, parse_url
from urlps._security.ip_utils import (
    _check_resolved_ips_safe,
    _parse_inet_aton_ipv4,
    _verify_connection_safe,
    is_ssrf_risk,
)


class TestObfuscatedIPv4SSRFBypass:
    """Regression: dotless octal/hex IPv4 forms bypassed SSRF protection.

    ``http://0x7f000001/`` is 127.0.0.1 to any inet_aton-based resolver, but
    the decimal check required an all-digit string within 32 bits (so it never
    tried octal) and the octal/hex check required exactly four dot-separated
    parts. Both dotless forms slipped through with SSRF protection enabled.
    """

    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            # Single 32-bit value, in each base.
            ("2130706433", "127.0.0.1"),
            ("0x7f000001", "127.0.0.1"),
            ("017700000001", "127.0.0.1"),
            ("0xc0a80101", "192.168.1.1"),
            # Short forms where the last part absorbs the remaining bytes.
            ("127.1", "127.0.0.1"),
            ("127.0.1", "127.0.0.1"),
            ("192.168.257", "192.168.1.1"),
            # Fully dotted, mixed bases.
            ("0177.0.0.1", "127.0.0.1"),
            ("0x7f.0x0.0x0.0x1", "127.0.0.1"),
            ("127.0.0.1", "127.0.0.1"),
        ],
    )
    def test_parses_like_inet_aton(self, host, expected):
        parsed = _parse_inet_aton_ipv4(host)
        assert parsed is not None, f"{host} should parse"
        assert str(parsed) == expected

    @pytest.mark.parametrize(
        "host",
        [
            "0x7f000001",
            "017700000001",
            "0xc0a80101",
            "127.1",
            "127.0.1",
            "2130706433",
            "0177.0.0.1",
            "0x7f.0x0.0x0.0x1",
        ],
    )
    def test_obfuscated_private_host_is_ssrf_risk(self, host):
        assert is_ssrf_risk(host) is True

    @pytest.mark.parametrize(
        "host",
        ["0x7f000001", "017700000001", "0xc0a80101", "127.1", "127.0.1"],
    )
    def test_parse_url_blocks_obfuscated_loopback(self, host):
        """End-to-end: these reached internal services with SSRF checks on."""
        with pytest.raises(InvalidURLError):
            parse_url(f"http://{host}/admin")

    def test_agrees_with_inet_aton(self):
        """Cross-check the grammar against the platform resolver."""
        for host in ["127.1", "127.0.1", "0x7f000001", "017700000001", "2130706433"]:
            expected = socket.inet_ntoa(socket.inet_aton(host))
            assert str(_parse_inet_aton_ipv4(host)) == expected

    @pytest.mark.parametrize(
        "host",
        ["example.com", "not-an-ip", "1.2.3.4.5", "0x", "999.999.999.999", "0xzz", ""],
    )
    def test_non_ipv4_hosts_are_not_parsed_as_addresses(self, host):
        assert _parse_inet_aton_ipv4(host) is None

    @pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1", "example.com", "api.github.com"])
    def test_public_hosts_are_not_flagged(self, host):
        """The fix must not create false positives on legitimate hosts."""
        assert is_ssrf_risk(host) is False
        assert parse_url(f"https://{host}/x").host is not None


class TestFailClosed:
    """A check that cannot reach a verdict must not report success."""

    def test_unparseable_resolved_address_is_unsafe(self):
        addr_info = [(2, 1, 6, "", ("not-an-ip", 80))]
        assert _check_resolved_ips_safe(addr_info) is False

    def test_empty_resolution_is_unsafe(self):
        assert _check_resolved_ips_safe([]) is False

    def test_private_resolved_address_is_unsafe(self):
        addr_info = [(2, 1, 6, "", ("127.0.0.1", 80))]
        assert _check_resolved_ips_safe(addr_info) is False

    def test_public_resolved_address_is_safe(self):
        addr_info = [(2, 1, 6, "", ("93.184.215.14", 80))]
        assert _check_resolved_ips_safe(addr_info) is True

    def test_mixed_addresses_are_unsafe_if_any_is_private(self):
        addr_info = [
            (2, 1, 6, "", ("93.184.215.14", 80)),
            (2, 1, 6, "", ("10.0.0.1", 80)),
        ]
        assert _check_resolved_ips_safe(addr_info) is False

    def test_empty_addr_info_cannot_verify_connection(self):
        assert _verify_connection_safe([], 1.0) is False


class TestPhishingDegradation:
    """Opting into a check and silently getting none is the worst failure mode."""

    def test_unavailable_database_is_reported_not_hidden(self):
        from urlps._security import collect_security_findings

        with patch(
            "urlps._security.check_against_phishing_db_detailed",
            return_value=(False, False),
        ):
            findings = collect_security_findings("https://example.com/", policy="strict", check_phishing=True)
        codes = {f.code for f in findings}
        assert "phishing_db_unavailable" in codes

    def test_unavailable_database_does_not_reject_the_url(self):
        """A degraded optional check must not turn into a hard parse failure."""
        with patch(
            "urlps._security.check_against_phishing_db_detailed",
            return_value=(False, False),
        ):
            url = parse_url("https://example.com/", check_phishing=True)
        assert url.host == "example.com"
        assert any(f.code == "phishing_db_unavailable" for f in url.security_findings)

    def test_available_database_with_clean_host_reports_nothing(self):
        with patch(
            "urlps._security.check_against_phishing_db_detailed",
            return_value=(False, True),
        ):
            url = parse_url("https://example.com/", check_phishing=True)
        assert url.security_findings == []

    def test_detected_phishing_still_rejects(self):
        with patch(
            "urlps._security.check_against_phishing_db_detailed",
            return_value=(True, True),
        ):
            with pytest.raises(InvalidURLError):
                parse_url("https://example.com/", check_phishing=True)


class TestDNSResolutionTimeout:
    """`timeout_seconds` previously bounded only the socket connect."""

    def test_slow_resolution_is_abandoned(self):
        from urlps._security.dns_guard import _resolve_addr_info

        def slow_getaddrinfo(*args, **kwargs):
            threading.Event().wait(10)  # never completes within the budget
            return []

        with patch("urlps._security.dns_guard.socket.getaddrinfo", slow_getaddrinfo):
            with pytest.raises(socket.timeout):
                _resolve_addr_info("slow.example.com", 0.2)

    def test_fast_resolution_returns_normally(self):
        from urlps._security.dns_guard import _resolve_addr_info

        expected = [(2, 1, 6, "", ("93.184.215.14", 80))]
        with patch("urlps._security.dns_guard.socket.getaddrinfo", return_value=expected):
            assert _resolve_addr_info("example.com", 5.0) == expected

    def test_no_timeout_still_resolves(self):
        from urlps._security.dns_guard import _resolve_addr_info

        expected = [(2, 1, 6, "", ("93.184.215.14", 80))]
        with patch("urlps._security.dns_guard.socket.getaddrinfo", return_value=expected):
            assert _resolve_addr_info("example.com", None) == expected


class TestDNSExceptionTypes:
    """DNS rebinding findings raise their matching typed subclass.

    validate_url_security previously wrapped every finding in a flat
    InvalidURLError regardless of which ErrorCode it carried, so a caller
    could not distinguish "rate limited" from "resolution failed" from
    "connection check failed" without inspecting .code by hand.
    """

    @pytest.mark.parametrize(
        ("error_code_name", "exception_cls_name"),
        [
            ("DNS_RATE_LIMITED", "DNSRateLimitError"),
            ("DNS_RESOLUTION_FAILED", "DNSResolutionError"),
            ("DNS_CONNECTION_FAILED", "DNSConnectionError"),
        ],
    )
    def test_dns_finding_raises_matching_subclass(self, error_code_name, exception_cls_name):
        from urlps import exceptions as exc_module

        error_code = getattr(exc_module.ErrorCode, error_code_name)
        expected_cls = getattr(exc_module, exception_cls_name)

        with patch(
            "urlps._security.check_dns_rebinding_detailed",
            return_value=(False, error_code),
        ):
            with pytest.raises(expected_cls):
                parse_url("https://example.com/", check_dns=True)

    def test_dns_exception_subclasses_remain_invalid_url_error(self):
        """Existing `except InvalidURLError` callers must be unaffected."""
        from urlps.exceptions import ErrorCode

        with patch(
            "urlps._security.check_dns_rebinding_detailed",
            return_value=(False, ErrorCode.DNS_RESOLUTION_FAILED),
        ):
            with pytest.raises(InvalidURLError):
                parse_url("https://example.com/", check_dns=True)


class TestConcurrency:
    """First concurrency coverage; shared mutable state must be synchronised.

    Note these assert *invariants*, not that a race reproduces. Under the GIL
    the unsynchronised versions often pass by luck, so these are guards for
    free-threaded builds (PEP 703) as much as for today.
    """

    def test_rate_limiter_never_exceeds_its_budget(self):
        budget = 5
        limiter = DNSRateLimiter(DNSRateLimiterConfig(max_lookups_per_second=budget, max_lookups_per_host=10_000))
        threads = 64
        barrier = threading.Barrier(threads)
        results = []
        results_lock = threading.Lock()

        def worker():
            barrier.wait()
            allowed = limiter.is_allowed("example.com")
            with results_lock:
                results.append(allowed)

        with ThreadPoolExecutor(max_workers=threads) as pool:
            list(pool.map(lambda _: worker(), range(threads)))

        assert sum(results) <= budget

    def test_concurrent_record_and_cleanup_do_not_raise(self):
        """cleanup iterates _host_lookups while record_lookup inserts into it."""
        limiter = DNSRateLimiter(
            DNSRateLimiterConfig(
                max_lookups_per_second=10_000,
                max_lookups_per_host=10_000,
                cleanup_interval_seconds=0.001,
                time_window_seconds=0.001,
            )
        )
        errors = []

        def worker(index):
            try:
                for i in range(200):
                    limiter.record_lookup(f"host-{index}-{i}.example.com")
                    limiter.is_allowed(f"host-{index}-{i}.example.com")
            except Exception as exc:
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, range(8)))

        assert errors == []

    def test_stats_snapshot_is_consistent_under_load(self):
        limiter = DNSRateLimiter(DNSRateLimiterConfig(max_lookups_per_second=1000, max_lookups_per_host=1000))
        errors = []

        def reader():
            try:
                for _ in range(200):
                    stats = limiter.stats()
                    assert stats["tokens"] >= 0
            except Exception as exc:
                errors.append(exc)

        def writer():
            for i in range(200):
                limiter.is_allowed(f"h{i}.example.com")

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(reader) for _ in range(3)]
            futures += [pool.submit(writer) for _ in range(3)]
            for future in futures:
                future.result()

        assert errors == []

    def test_global_limiter_is_created_once(self):
        """Racing the lazy initialiser must not discard a live limiter."""
        import urlps._security.dns_guard as dns_guard

        original = dns_guard._GLOBAL_RATE_LIMITER
        try:
            dns_guard._GLOBAL_RATE_LIMITER = None
            barrier = threading.Barrier(32)

            def get():
                barrier.wait()
                return dns_guard.get_dns_rate_limiter()

            with ThreadPoolExecutor(max_workers=32) as pool:
                instances = list(pool.map(lambda _: get(), range(32)))

            assert len({id(instance) for instance in instances}) == 1
        finally:
            dns_guard._GLOBAL_RATE_LIMITER = original

    def test_concurrent_parsing_is_safe(self):
        """The common case: many threads parsing through the shared caches."""
        urls = [f"https://example{i}.com/a/b?q={i}" for i in range(100)]
        errors = []

        def worker(url):
            try:
                parsed = parse_url(url)
                assert parsed.host is not None
            except Exception as exc:
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(worker, urls * 4))

        assert errors == []

    @pytest.mark.slow
    def test_rate_limiter_holds_its_budget_under_sustained_load(self):
        """The other rate-limiter tests above run one short burst. A token
        bucket can drift once multiple refill windows and cleanup passes
        actually happen back to back under contention -- that only shows up
        over a longer soak, not a single burst, so it needs its own test
        rather than just cranking up the numbers in the existing ones."""
        budget = 20
        limiter = DNSRateLimiter(
            DNSRateLimiterConfig(
                max_lookups_per_second=budget,
                max_lookups_per_host=10_000,
                cleanup_interval_seconds=0.05,
                time_window_seconds=1.0,
            )
        )
        duration_seconds = 3.0
        start = time.monotonic()
        deadline = start + duration_seconds
        errors = []
        allowed_timestamps = []
        timestamps_lock = threading.Lock()

        def worker():
            try:
                while time.monotonic() < deadline:
                    if limiter.is_allowed("sustained.example.com"):
                        now = time.monotonic()
                        with timestamps_lock:
                            allowed_timestamps.append(now)
            except Exception as exc:
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(worker) for _ in range(8)]
            for future in futures:
                future.result()

        assert errors == []

        # This is a continuous token bucket (starts with `budget` tokens,
        # refills at `budget`/second), not a fixed-window counter -- so the
        # invariant isn't "<= budget per calendar second", it's "cumulative
        # allowed count by time t never exceeds the initial burst plus what
        # refilled by then". A small tolerance absorbs scheduling jitter
        # between "is_allowed returned True" and "we recorded the
        # timestamp"; the point of this soak is to catch drift across many
        # refill/cleanup cycles, not to nail sub-millisecond timing.
        allowed_timestamps.sort()
        tolerance = 2
        for index, timestamp in enumerate(allowed_timestamps, start=1):
            elapsed = timestamp - start
            capacity_by_now = budget + budget * elapsed
            assert index <= capacity_by_now + tolerance, (
                f"{index} lookups allowed by t={elapsed:.3f}s, but capacity was only "
                f"~{capacity_by_now:.1f} (budget={budget})"
            )
