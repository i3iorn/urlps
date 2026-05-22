"""Tests for DNS rate limiting."""
import time
import pytest
from src.urlps._security import (
    DNSRateLimiter,
    get_dns_rate_limiter,
    reset_dns_rate_limiter,
    check_dns_rate_limit,
)


class TestDNSRateLimiterBasics:
    """Test basic DNS rate limiter functionality."""

    def test_rate_limiter_initialization(self):
        """Rate limiter should initialize with default values."""
        limiter = DNSRateLimiter()
        assert limiter.max_lookups_per_second == 10.0
        assert limiter.max_lookups_per_host == 3
        assert limiter.time_window == 60.0
        assert limiter.tokens > 0

    def test_custom_rate_limits(self):
        """Should support custom rate limit values."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=5.0,
            max_lookups_per_host=2,
            time_window=30.0
        )
        assert limiter.max_lookups_per_second == 5.0
        assert limiter.max_lookups_per_host == 2
        assert limiter.time_window == 30.0

    def test_first_lookup_allowed(self):
        """First lookup should always be allowed."""
        limiter = DNSRateLimiter()
        assert limiter.is_allowed("example.com")

    def test_multiple_unique_hosts_allowed(self):
        """Multiple unique hosts should be allowed (global rate permitting)."""
        limiter = DNSRateLimiter(max_lookups_per_second=100.0)
        assert limiter.is_allowed("example1.com")
        assert limiter.is_allowed("example2.com")
        assert limiter.is_allowed("example3.com")


class TestPerHostRateLimit:
    """Test per-host rate limiting."""

    def test_same_host_limit(self):
        """Same host should be rate limited after max lookups."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=100.0,  # High global limit
            max_lookups_per_host=3
        )

        # First 3 lookups should succeed
        assert limiter.is_allowed("example.com")
        assert limiter.is_allowed("example.com")
        assert limiter.is_allowed("example.com")

        # 4th lookup should be blocked
        assert not limiter.is_allowed("example.com")

    def test_different_hosts_independent(self):
        """Different hosts should have independent limits."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=100.0,
            max_lookups_per_host=2
        )

        # Host A: 2 lookups
        assert limiter.is_allowed("hostA.com")
        assert limiter.is_allowed("hostA.com")
        assert not limiter.is_allowed("hostA.com")  # 3rd blocked

        # Host B: should still work
        assert limiter.is_allowed("hostB.com")
        assert limiter.is_allowed("hostB.com")
        assert not limiter.is_allowed("hostB.com")  # 3rd blocked

    def test_time_window_expiry(self):
        """Old lookups should expire after time window."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=100.0,
            max_lookups_per_host=2,
            time_window=0.1  # 100ms window for testing
        )

        # Use up limit
        assert limiter.is_allowed("example.com")
        assert limiter.is_allowed("example.com")
        assert not limiter.is_allowed("example.com")

        # Wait for window to expire
        time.sleep(0.15)

        # Should be allowed again
        assert limiter.is_allowed("example.com")


class TestGlobalRateLimit:
    """Test global rate limiting."""

    def test_global_rate_limit_tokens(self):
        """Should consume tokens from global bucket."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=5.0,
            max_lookups_per_host=100  # High per-host limit
        )

        initial_tokens = limiter.tokens

        # Each lookup consumes 1 token
        assert limiter.is_allowed("host1.com")
        assert limiter.tokens < initial_tokens

    def test_global_rate_limit_exhaustion(self):
        """Should block when global tokens exhausted."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=3.0,
            max_lookups_per_host=100
        )

        # Consume all tokens
        assert limiter.is_allowed("host1.com")
        assert limiter.is_allowed("host2.com")
        assert limiter.is_allowed("host3.com")

        # Next lookup should fail (no tokens left)
        assert not limiter.is_allowed("host4.com")

    def test_token_refill(self):
        """Tokens should refill over time."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=10.0,
            max_lookups_per_host=100
        )

        # Consume some tokens
        limiter.is_allowed("host1.com")
        limiter.is_allowed("host2.com")
        tokens_after = limiter.tokens

        # Wait and check refill
        time.sleep(0.3)  # Should refill ~3 tokens
        limiter._refill_tokens()
        assert limiter.tokens > tokens_after


class TestRateLimiterReset:
    """Test rate limiter reset functionality."""

    def test_reset_clears_state(self):
        """Reset should clear all rate limiting state."""
        limiter = DNSRateLimiter(max_lookups_per_host=2)

        # Use up limit
        limiter.is_allowed("example.com")
        limiter.is_allowed("example.com")
        assert not limiter.is_allowed("example.com")

        # Reset
        limiter.reset()

        # Should work again
        assert limiter.is_allowed("example.com")

    def test_reset_refills_tokens(self):
        """Reset should refill token bucket."""
        limiter = DNSRateLimiter(max_lookups_per_second=5.0)

        # Consume tokens
        for _ in range(5):
            limiter.is_allowed(f"host{_}.com")

        # Tokens should be low
        assert limiter.tokens < 1.0

        # Reset
        limiter.reset()

        # Tokens should be refilled
        assert limiter.tokens == 5.0


class TestRateLimiterStats:
    """Test rate limiter statistics."""

    def test_get_stats(self):
        """Should return current statistics."""
        limiter = DNSRateLimiter(max_lookups_per_second=10.0)

        stats = limiter.get_stats()
        assert "tokens" in stats
        assert "tracked_hosts" in stats
        assert "total_recent_lookups" in stats

    def test_stats_track_hosts(self):
        """Stats should track number of hosts."""
        limiter = DNSRateLimiter()

        limiter.is_allowed("host1.com")
        limiter.is_allowed("host2.com")
        limiter.is_allowed("host3.com")

        stats = limiter.get_stats()
        assert stats["tracked_hosts"] == 3

    def test_stats_track_lookups(self):
        """Stats should track total lookups."""
        limiter = DNSRateLimiter()

        limiter.is_allowed("host1.com")
        limiter.is_allowed("host1.com")
        limiter.is_allowed("host2.com")

        stats = limiter.get_stats()
        assert stats["total_recent_lookups"] == 3


class TestCleanupBehavior:
    """Test cleanup of old entries."""

    def test_cleanup_removes_old_hosts(self):
        """Cleanup should remove hosts with no recent lookups."""
        limiter = DNSRateLimiter(
            time_window=0.1,  # 100ms
            cleanup_interval=0.05  # 50ms
        )

        # Add some hosts
        limiter.is_allowed("old-host.com")
        assert limiter.get_stats()["tracked_hosts"] == 1

        # Wait for entries to expire
        time.sleep(0.15)

        # Trigger cleanup by making new request
        limiter.is_allowed("new-host.com")

        # Old host should be cleaned up
        stats = limiter.get_stats()
        assert stats["tracked_hosts"] == 1  # Only new-host

    def test_cleanup_preserves_recent_hosts(self):
        """Cleanup should keep hosts with recent lookups."""
        limiter = DNSRateLimiter(
            time_window=10.0,  # Long window
            cleanup_interval=0.05
        )

        limiter.is_allowed("recent-host.com")
        time.sleep(0.1)  # Trigger cleanup
        limiter.is_allowed("another-host.com")

        stats = limiter.get_stats()
        assert stats["tracked_hosts"] == 2  # Both kept


class TestGlobalRateLimiter:
    """Test global rate limiter singleton."""

    def test_get_global_limiter(self):
        """Should get or create global limiter."""
        limiter = get_dns_rate_limiter()
        assert isinstance(limiter, DNSRateLimiter)

        # Should return same instance
        limiter2 = get_dns_rate_limiter()
        assert limiter is limiter2

    def test_reset_global_limiter(self):
        """Should reset global limiter state."""
        limiter = get_dns_rate_limiter()

        # Use up some limit
        limiter.is_allowed("test.com")
        limiter.is_allowed("test.com")

        # Reset
        reset_dns_rate_limiter()

        # Should be cleared
        assert limiter.is_allowed("test.com")

    def test_check_dns_rate_limit_convenience(self):
        """Convenience function should use global limiter."""
        reset_dns_rate_limiter()  # Clean slate

        # Should use global limiter
        assert check_dns_rate_limit("example.com")

        # Check that it's actually enforcing limits
        limiter = get_dns_rate_limiter()
        limiter.max_lookups_per_host = 1  # Set to 1 for testing

        # Second call should fail
        assert not check_dns_rate_limit("example.com")


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_hostname(self):
        """Empty hostname should return False."""
        limiter = DNSRateLimiter()
        assert not limiter.is_allowed("")

    def test_none_hostname(self):
        """None hostname should return False."""
        limiter = DNSRateLimiter()
        assert not limiter.is_allowed(None)

    def test_invalid_hostname_types(self):
        """Non-string hostnames should return False."""
        limiter = DNSRateLimiter()
        assert not limiter.is_allowed(123)
        assert not limiter.is_allowed([])
        assert not limiter.is_allowed({})

    def test_record_lookup_without_check(self):
        """Should be able to record lookups without checking."""
        limiter = DNSRateLimiter(max_lookups_per_host=2)

        # Record lookups (e.g., from cache)
        limiter.record_lookup("cached.com")
        limiter.record_lookup("cached.com")

        # Next check should be rate limited
        assert not limiter.is_allowed("cached.com")

    def test_very_high_rate_limit(self):
        """Should handle very high rate limits."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=1000.0,
            max_lookups_per_host=100
        )

        # Should allow many lookups
        for i in range(50):
            assert limiter.is_allowed(f"host{i}.com")


class TestDoSPrevention:
    """Test DoS attack prevention scenarios."""

    def test_prevents_single_host_flooding(self):
        """Should prevent flooding from single host."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=100.0,
            max_lookups_per_host=3
        )

        # Attacker tries to flood with same host
        for _ in range(10):
            result = limiter.is_allowed("attacker.com")
            if _ < 3:
                assert result  # First 3 allowed
            else:
                assert not result  # Rest blocked

    def test_prevents_unique_host_flooding(self):
        """Should prevent flooding with unique hosts."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=5.0,
            max_lookups_per_host=100
        )

        # Attacker tries to flood with unique hosts
        allowed = 0
        for i in range(20):
            if limiter.is_allowed(f"attacker{i}.com"):
                allowed += 1

        # Should only allow ~5 lookups (based on global limit)
        assert allowed <= 6  # Allow small margin for timing

    def test_legitimate_usage_pattern(self):
        """Should allow legitimate usage patterns."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=10.0,
            max_lookups_per_host=3
        )

        # Legitimate app checking multiple unique URLs
        hosts = [f"site{i}.com" for i in range(8)]

        # Should allow all (under global limit)
        for host in hosts:
            assert limiter.is_allowed(host)

    def test_burst_then_steady_state(self):
        """Should handle burst then steady-state pattern."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=5.0,
            max_lookups_per_host=10
        )

        # Burst: use all tokens
        for i in range(5):
            limiter.is_allowed(f"burst{i}.com")

        # Should be rate limited
        assert not limiter.is_allowed("burst6.com")

        # Wait for refill
        time.sleep(0.3)

        # Should work again
        assert limiter.is_allowed("steady.com")


class TestIntegrationScenarios:
    """Test real-world integration scenarios."""

    def test_web_crawler_scenario(self):
        """Web crawler checking many URLs."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=10.0,
            max_lookups_per_host=5
        )

        # Crawler finds many URLs from same domain
        for i in range(10):
            result = limiter.is_allowed("example.com")
            if i < 5:
                assert result  # First 5 allowed
            else:
                assert not result  # Per-host limit hit

    def test_api_gateway_scenario(self):
        """API gateway validating webhook URLs."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=20.0,
            max_lookups_per_host=2
        )

        # Multiple users registering webhooks
        webhooks = [
            ("user1", "webhook1.user1.com"),
            ("user1", "webhook2.user1.com"),
            ("user2", "webhook.user2.com"),
            ("user3", "callback.user3.com"),
        ]

        # Should allow reasonable usage
        for user, webhook in webhooks:
            assert limiter.is_allowed(webhook)

    def test_email_filter_scenario(self):
        """Email filter checking URLs in messages."""
        limiter = DNSRateLimiter(
            max_lookups_per_second=15.0,
            max_lookups_per_host=3
        )

        # Email with multiple links
        email_links = [
            "example.com",
            "example.com",  # Same link repeated
            "other-site.com",
            "third-site.com",
        ]

        # Should allow all (under limits)
        for link in email_links:
            assert limiter.is_allowed(link)
