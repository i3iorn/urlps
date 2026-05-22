"""DNS rebinding checks and DNS lookup rate limiting."""
from __future__ import annotations

import logging
import secrets
import socket
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple, cast

from ..constants import (
    DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS,
    DEFAULT_DNS_LOOKUPS_PER_HOST,
    DEFAULT_DNS_LOOKUPS_PER_SECOND,
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_DNS_TIME_WINDOW_SECONDS,
)
from ..exceptions import ErrorCode
from .ip_utils import _check_direct_ip_safe, _check_resolved_ips_safe, _strip_ipv6_brackets, _verify_connection_safe

logger = logging.getLogger(__name__)


def _jitter_seconds(max_jitter_seconds: float) -> float:
    """Return cryptographically strong jitter in [0, max_jitter_seconds]."""
    if max_jitter_seconds <= 0:
        return 0.0
    scale = 1_000_000
    return (secrets.randbelow(scale + 1) / scale) * max_jitter_seconds


class DNSRateLimiter:
    """Rate limiter for DNS lookups to prevent DoS attacks."""

    def __init__(
        self,
        max_lookups_per_second: float = DEFAULT_DNS_LOOKUPS_PER_SECOND,
        max_lookups_per_host: int = DEFAULT_DNS_LOOKUPS_PER_HOST,
        time_window: float = DEFAULT_DNS_TIME_WINDOW_SECONDS,
        cleanup_interval: float = DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS,
    ):
        self.max_lookups_per_second = max_lookups_per_second
        self.max_lookups_per_host = max_lookups_per_host
        self.time_window = time_window
        self.cleanup_interval = cleanup_interval

        self.tokens = max_lookups_per_second
        self.last_update = time.time()
        self.host_lookups: Dict[str, Deque[float]] = defaultdict(deque)
        self.last_cleanup = time.time()

    def _refill_tokens(self) -> None:
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.max_lookups_per_second, self.tokens + elapsed * self.max_lookups_per_second)
        self.last_update = now

    def _cleanup_old_entries(self) -> None:
        now = time.time()
        if now - self.last_cleanup < self.cleanup_interval:
            return

        cutoff = now - self.time_window
        hosts_to_remove = []
        for host, timestamps in self.host_lookups.items():
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()
            if not timestamps:
                hosts_to_remove.append(host)

        for host in hosts_to_remove:
            del self.host_lookups[host]

        self.last_cleanup = now

    def is_allowed(self, host: str) -> bool:
        if not isinstance(host, str) or not host:
            return False

        now = time.time()

        self._refill_tokens()
        if self.tokens < 1.0:
            return False

        timestamps = self.host_lookups[host]
        cutoff = now - self.time_window
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        if len(timestamps) >= self.max_lookups_per_host:
            return False

        self.tokens -= 1.0
        timestamps.append(now)
        self._cleanup_old_entries()
        return True

    def record_lookup(self, host: str) -> None:
        if not isinstance(host, str) or not host:
            return

        self.host_lookups[host].append(time.time())
        self._cleanup_old_entries()

    def reset(self) -> None:
        self.tokens = self.max_lookups_per_second
        self.last_update = time.time()
        self.host_lookups.clear()
        self.last_cleanup = time.time()

    def get_stats(self) -> dict:
        self._refill_tokens()
        total_lookups = sum(len(timestamps) for timestamps in self.host_lookups.values())
        return {
            "tokens": self.tokens,
            "tracked_hosts": len(self.host_lookups),
            "total_recent_lookups": total_lookups,
        }


_dns_rate_limiter: Optional[DNSRateLimiter] = None


def get_dns_rate_limiter() -> DNSRateLimiter:
    """Get or create the global DNS rate limiter."""
    global _dns_rate_limiter
    if _dns_rate_limiter is None:
        _dns_rate_limiter = DNSRateLimiter()
    return cast(DNSRateLimiter, _dns_rate_limiter)


def reset_dns_rate_limiter() -> None:
    """Reset the global DNS rate limiter."""
    global _dns_rate_limiter
    if _dns_rate_limiter is not None:
        _dns_rate_limiter.reset()


def check_dns_rate_limit(host: str) -> bool:
    """Check if DNS lookup for this host is allowed under rate limits."""
    return get_dns_rate_limiter().is_allowed(host)


def check_dns_rebinding_detailed(
    host: str,
    timeout: Optional[float] = None,
    enforce_rate_limit: bool = True,
    retries: int = 2,
    backoff_base_seconds: float = 0.05,
    backoff_jitter_seconds: float = 0.02,
) -> Tuple[bool, Optional[ErrorCode]]:
    """Check DNS rebinding risk and return deterministic status."""
    if not isinstance(host, str) or not host:
        return False, ErrorCode.DNS_RESOLUTION_FAILED

    timeout_seconds = DEFAULT_DNS_TIMEOUT if timeout is None else timeout
    host = _strip_ipv6_brackets(host)

    direct_result = _check_direct_ip_safe(host)
    if direct_result is not None:
        return direct_result, None if direct_result else ErrorCode.SSRF_RISK

    if enforce_rate_limit:
        limiter = get_dns_rate_limiter()
        if not limiter.is_allowed(host):
            logger.warning("dns_check_blocked rate_limit host=%s", host)
            return False, ErrorCode.DNS_RATE_LIMITED

    last_error: Optional[ErrorCode] = None
    max_attempts = max(1, retries + 1)

    for attempt in range(max_attempts):
        try:
            addr_info = socket.getaddrinfo(host, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if not _check_resolved_ips_safe(addr_info):
                return False, ErrorCode.SSRF_RISK
            if not _verify_connection_safe(addr_info, timeout_seconds):
                return False, ErrorCode.DNS_CONNECTION_FAILED
            return True, None
        except socket.gaierror:
            last_error = ErrorCode.DNS_RESOLUTION_FAILED
        except (socket.timeout, OSError):
            last_error = ErrorCode.DNS_CONNECTION_FAILED

        if attempt + 1 < max_attempts:
            sleep_seconds = (backoff_base_seconds * (2 ** attempt)) + _jitter_seconds(backoff_jitter_seconds)
            time.sleep(sleep_seconds)

    return False, last_error or ErrorCode.DNS_RESOLUTION_FAILED


def check_dns_rebinding(
    host: str,
    timeout: Optional[float] = None,
    enforce_rate_limit: bool = True,
    retries: int = 2,
    backoff_base_seconds: float = 0.05,
    backoff_jitter_seconds: float = 0.02,
) -> bool:
    """Backward-compatible boolean wrapper around detailed DNS rebinding checks."""
    safe, _ = check_dns_rebinding_detailed(
        host,
        timeout=timeout,
        enforce_rate_limit=enforce_rate_limit,
        retries=retries,
        backoff_base_seconds=backoff_base_seconds,
        backoff_jitter_seconds=backoff_jitter_seconds,
    )
    return safe

