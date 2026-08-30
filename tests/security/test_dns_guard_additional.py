"""Additional coverage for _security/dns_guard.py: config validation, rate
limiter constructor validation, stats(), and rate-limit-blocked path.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from urlps._security.dns_guard import (
    DNSRateLimiter,
    DNSRateLimiterConfig,
    check_dns_rebinding_detailed,
    get_dns_rate_limiter,
    reset_dns_rate_limiter,
)
from urlps.exceptions import DNSRateLimiterError, ErrorCode


class TestDNSRateLimiterConfigValidation:
    def test_rejects_non_positive_max_lookups_per_second(self):
        with pytest.raises(DNSRateLimiterError, match="max_lookups_per_second"):
            DNSRateLimiterConfig(max_lookups_per_second=0)

    def test_rejects_non_positive_max_lookups_per_host(self):
        with pytest.raises(DNSRateLimiterError, match="max_lookups_per_host"):
            DNSRateLimiterConfig(max_lookups_per_host=0)

    def test_rejects_non_positive_time_window_seconds(self):
        with pytest.raises(DNSRateLimiterError, match="time_window_seconds"):
            DNSRateLimiterConfig(time_window_seconds=0)

    def test_rejects_non_positive_cleanup_interval_seconds(self):
        with pytest.raises(DNSRateLimiterError, match="cleanup_interval_seconds"):
            DNSRateLimiterConfig(cleanup_interval_seconds=0)


class TestDNSRateLimiterConstructorValidation:
    def test_rejects_non_config_instance(self):
        with pytest.raises(DNSRateLimiterError, match="DNSRateLimiterConfig"):
            DNSRateLimiter(config="not-a-config")  # type: ignore[arg-type]

    def test_rejects_non_callable_time_provider(self):
        with pytest.raises(DNSRateLimiterError, match="time_provider must be callable"):
            DNSRateLimiter(time_provider="not-callable")  # type: ignore[arg-type]

    def test_rejects_time_provider_returning_non_numeric(self):
        with pytest.raises(DNSRateLimiterError, match="numeric timestamp"):
            DNSRateLimiter(time_provider=lambda: "not-a-number")


class TestDNSRateLimiterStats:
    def test_stats_reports_tokens_and_tracked_hosts(self):
        limiter = DNSRateLimiter()
        limiter.is_allowed("example.com")
        stats = limiter.stats()
        assert stats["tracked_hosts"] >= 1.0
        assert "tokens" in stats
        assert "total_recent_lookups" in stats


class TestResetDnsRateLimiter:
    def test_reset_dns_rate_limiter_resets_global_limiter(self):
        get_dns_rate_limiter().is_allowed("example.com")
        reset_dns_rate_limiter()
        stats = get_dns_rate_limiter().stats()
        assert stats["tracked_hosts"] == 0.0


class TestCheckDnsRebindingDetailedTimeoutAndRateLimit:
    def test_non_positive_timeout_fails_closed(self):
        safe, error = check_dns_rebinding_detailed("example.com", timeout_seconds=0)
        assert safe is False
        assert error == ErrorCode.DNS_CONNECTION_FAILED

    def test_rate_limit_blocks_lookup(self):
        limiter = DNSRateLimiter(DNSRateLimiterConfig(max_lookups_per_second=1, max_lookups_per_host=1))
        # Exhaust the limiter for this host.
        limiter.is_allowed("example.com")
        limiter.is_allowed("example.com")
        safe, error = check_dns_rebinding_detailed("example.com", limiter=limiter)
        assert safe is False
        assert error == ErrorCode.DNS_RATE_LIMITED

    def test_socket_gaierror_reports_resolution_failed(self):
        import socket

        with patch("urlps._security.dns_guard._resolve_addr_info", side_effect=socket.gaierror("boom")):
            safe, error = check_dns_rebinding_detailed(
                "nonexistent.invalid",
                retries=0,
                backoff_base_seconds=0,
            )
        assert safe is False
        assert error == ErrorCode.DNS_RESOLUTION_FAILED

    def test_connect_timeout_reports_connection_failed(self):
        with patch("urlps._security.dns_guard._resolve_addr_info", side_effect=TimeoutError("timed out")):
            safe, error = check_dns_rebinding_detailed(
                "example.com",
                retries=0,
                backoff_base_seconds=0,
            )
        assert safe is False
        assert error == ErrorCode.DNS_CONNECTION_FAILED
