"""DNS rebinding protection and DNS lookup rate limiting.

This module provides:
- A deterministic, testable DNSRateLimiter with no global state.
- DNS rebinding checks with explicit error codes and strict input validation.
"""

from __future__ import annotations

import logging
import secrets
import socket
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Optional, Tuple

from ..constants import (
    DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS,
    DEFAULT_DNS_LOOKUPS_PER_HOST,
    DEFAULT_DNS_LOOKUPS_PER_SECOND,
    DEFAULT_DNS_TIME_WINDOW_SECONDS,
    DEFAULT_DNS_TIMEOUT,
)
from ..exceptions import DNSRateLimiterError, ErrorCode
from .ip_utils import (
    AddrInfo,
    _check_direct_ip_safe,
    _check_resolved_ips_safe,
    _strip_ipv6_brackets,
    _verify_connection_safe,
)

logger = logging.getLogger(__name__)
_GLOBAL_RATE_LIMITER: Optional["DNSRateLimiter"] = None
_GLOBAL_RATE_LIMITER_LOCK = threading.Lock()


TimeProvider = Callable[[], float]


@dataclass(frozen=True)
class DNSRateLimiterConfig:
    """Configuration for DNSRateLimiter."""

    max_lookups_per_second: float = DEFAULT_DNS_LOOKUPS_PER_SECOND
    max_lookups_per_host: int = DEFAULT_DNS_LOOKUPS_PER_HOST
    time_window_seconds: float = DEFAULT_DNS_TIME_WINDOW_SECONDS
    cleanup_interval_seconds: float = DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS

    def __post_init__(self):
        if self.max_lookups_per_second <= 0:
            raise DNSRateLimiterError("max_lookups_per_second must be positive")
        if self.max_lookups_per_host <= 0:
            raise DNSRateLimiterError("max_lookups_per_host must be positive")
        if self.time_window_seconds <= 0:
            raise DNSRateLimiterError("time_window_seconds must be positive")
        if self.cleanup_interval_seconds <= 0:
            raise DNSRateLimiterError("cleanup_interval_seconds must be positive")



class DNSRateLimiter:
    """Token-bucket DNS rate limiter with per-host tracking.

    The limiter is deterministic, side-effect free outside its own state,
    and uses an injected time provider for testability.
    """

    def __init__(
        self,
        config: Optional[DNSRateLimiterConfig] = None,
        time_provider: TimeProvider = time.time,
    ) -> None:
        if config is None:
            config = DNSRateLimiterConfig()

        if not isinstance(config, DNSRateLimiterConfig):
            raise DNSRateLimiterError("config must be an instance of DNSRateLimiterConfig")
        if not callable(time_provider):
            raise DNSRateLimiterError("time_provider must be callable")
        if not isinstance(time_provider(), (int, float)):
            raise DNSRateLimiterError("time_provider must return a numeric timestamp")

        self._config = config
        self._time_provider = time_provider

        now = self._time_provider()
        self._tokens: float = config.max_lookups_per_second
        self._last_update_seconds: float = now
        self._host_lookups: Dict[str, Deque[float]] = defaultdict(deque)
        self._last_cleanup_seconds: float = now
        # A rate limit is a security control, so its read-modify-write cycles
        # must be atomic. The GIL happens to mask most interleavings today, but
        # it is not a synchronisation primitive and does not exist at all on
        # free-threaded builds (PEP 703). This also prevents a concurrent
        # record_lookup() from mutating _host_lookups while _cleanup_old_entries
        # iterates it, which would raise RuntimeError.
        self._lock = threading.Lock()

    @property
    def config(self) -> DNSRateLimiterConfig:
        """Return the current configuration."""
        return self._config

    def _now(self) -> float:
        return self._time_provider()

    def _refill_tokens(self) -> None:
        now = self._now()
        elapsed_seconds = max(0.0, now - self._last_update_seconds)
        refill_amount = elapsed_seconds * self._config.max_lookups_per_second
        self._tokens = min(self._config.max_lookups_per_second, self._tokens + refill_amount)
        self._last_update_seconds = now

    def _remove_stale_timestamps(self, timestamps: Deque[float], cutoff_seconds: float) -> None:
        while timestamps and timestamps[0] < cutoff_seconds:
            timestamps.popleft()

    def _cleanup_old_entries(self) -> None:
        now = self._now()
        if now - self._last_cleanup_seconds < self._config.cleanup_interval_seconds:
            return

        cutoff_seconds = now - self._config.time_window_seconds
        hosts_to_remove: list[str] = []

        for host, timestamps in self._host_lookups.items():
            self._remove_stale_timestamps(timestamps, cutoff_seconds)
            if not timestamps:
                hosts_to_remove.append(host)

        for host in hosts_to_remove:
            del self._host_lookups[host]

        self._last_cleanup_seconds = now

    def is_allowed(self, host: str) -> bool:
        """Return True if a DNS lookup for host is allowed under current limits.

        Invalid host values are treated as disallowed.
        """
        if not isinstance(host, str) or not host.strip():
            logger.warning("dns_rate_limit_invalid_host", extra={"event": "dns_rate_limit_invalid_host"})
            return False

        # The whole check-and-consume must be atomic: testing the budget and
        # then decrementing it in separate steps lets concurrent callers each
        # pass the check and overspend it.
        with self._lock:
            self._refill_tokens()
            if self._tokens < 1.0:
                logger.info(
                    "dns_rate_limit_global_exceeded",
                    extra={"event": "dns_rate_limit_global_exceeded"},
                )
                return False

            now = self._now()
            cutoff_seconds = now - self._config.time_window_seconds
            timestamps = self._host_lookups[host]

            self._remove_stale_timestamps(timestamps, cutoff_seconds)

            if len(timestamps) >= self._config.max_lookups_per_host:
                logger.info(
                    "dns_rate_limit_host_exceeded",
                    extra={"event": "dns_rate_limit_host_exceeded", "host": host},
                )
                return False

            self._tokens -= 1.0
            timestamps.append(now)
            self._cleanup_old_entries()
            return True

    def record_lookup(self, host: str) -> None:
        """Record a DNS lookup for host without enforcing limits."""
        if not isinstance(host, str) or not host.strip():
            logger.warning("dns_rate_limit_invalid_host_record", extra={"event": "dns_rate_limit_invalid_host_record"})
            return

        with self._lock:
            now = self._now()
            self._host_lookups[host].append(now)
            self._cleanup_old_entries()

    def reset(self) -> None:
        """Reset limiter state to initial configuration."""
        with self._lock:
            now = self._now()
            self._tokens = self._config.max_lookups_per_second
            self._last_update_seconds = now
            self._host_lookups.clear()
            self._last_cleanup_seconds = now

    def stats(self) -> Dict[str, float]:
        """Return current limiter statistics.

        Takes the lock so the snapshot is internally consistent rather than
        read while another thread is mid-update.
        """
        with self._lock:
            self._refill_tokens()
            total_recent_lookups = sum(
                len(timestamps) for timestamps in self._host_lookups.values()
            )
            return {
                "tokens": float(self._tokens),
                "tracked_hosts": float(len(self._host_lookups)),
                "total_recent_lookups": float(total_recent_lookups),
            }


def _secure_jitter_seconds(max_jitter_seconds: float) -> float:
    """Return cryptographically strong jitter in [0, max_jitter_seconds]."""
    if max_jitter_seconds <= 0:
        return 0.0

    scale = 1_000_000
    random_int = secrets.randbelow(scale + 1)
    jitter_fraction = random_int / scale
    return jitter_fraction * max_jitter_seconds


def _validate_host(host: str) -> Optional[str]:
    """Return a normalized host or None if invalid."""
    if not isinstance(host, str):
        return None
    stripped = host.strip()
    if not stripped:
        return None
    return _strip_ipv6_brackets(stripped)


def _resolve_addr_info(
    host: str, timeout_seconds: Optional[float] = None
) -> list[Tuple[int, int, int, str, tuple]]:
    """Resolve host to address info, raising socket.gaierror on failure.

    ``socket.getaddrinfo`` takes no timeout argument and is bounded only by the
    OS resolver, which under packet loss can block for 5-30 seconds. The
    documented ``timeout_seconds`` previously applied only to the subsequent
    socket connect, so a caller asking for a 2s budget could still block far
    longer. ``socket.setdefaulttimeout`` does not affect getaddrinfo either,
    so the lookup is run in a worker thread and abandoned on timeout.

    The abandoned thread is a daemon and will finish on its own; we simply
    stop waiting for it.
    """
    # Port 80 is arbitrary here; we only care about address resolution.
    def _lookup() -> list[Tuple[int, int, int, str, tuple]]:
        return list(socket.getaddrinfo(host, 80, socket.AF_UNSPEC, socket.SOCK_STREAM))

    if timeout_seconds is None or timeout_seconds <= 0:
        return _lookup()

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="urlps-dns")
    try:
        future = executor.submit(_lookup)
        try:
            return future.result(timeout=timeout_seconds)
        except FuturesTimeoutError as exc:
            raise socket.timeout(
                f"DNS resolution for {host!r} exceeded {timeout_seconds}s"
            ) from exc
    finally:
        # Do not block on an in-flight lookup we have already given up on.
        executor.shutdown(wait=False)


def check_dns_rate_limit(host: str, limiter: Optional[DNSRateLimiter] = None) -> bool:
    """Check if DNS lookup for host is allowed under the provided limiter.

    Preferred usage: pass an explicit limiter instance. The process-global
    fallback exists for backward compatibility.

    Args:
        host: Hostname or IP string to check.
        limiter: DNSRateLimiter instance to enforce limits.

    Returns:
        True if lookup is allowed, False otherwise.
    """
    effective_limiter = get_dns_rate_limiter() if limiter is None else limiter
    return effective_limiter.is_allowed(host)


def get_dns_rate_limiter() -> DNSRateLimiter:
    """Get or create the process-global DNS rate limiter.

    Compatibility API. Prefer dependency-injected limiter instances via
    parse_url(..., dns_rate_limiter=...) or SecurityPolicy(..., dns_rate_limiter=...).
    """
    global _GLOBAL_RATE_LIMITER
    # Double-checked locking: without the lock, two threads racing the first
    # call each build a limiter and one is discarded along with any lookups
    # already recorded against it, silently loosening the limit.
    if _GLOBAL_RATE_LIMITER is None:
        with _GLOBAL_RATE_LIMITER_LOCK:
            if _GLOBAL_RATE_LIMITER is None:
                _GLOBAL_RATE_LIMITER = DNSRateLimiter()
    return _GLOBAL_RATE_LIMITER


def reset_dns_rate_limiter() -> None:
    """Reset the process-global DNS rate limiter state.

    Compatibility API for integrations still using the process-global limiter.
    """
    limiter = get_dns_rate_limiter()
    limiter.reset()


def check_dns_rebinding_detailed(
    host: str,
    timeout_seconds: Optional[float] = None,
    timeout: Optional[float] = None,
    enforce_rate_limit: bool = True,
    retries: int = 2,
    backoff_base_seconds: float = 0.05,
    backoff_jitter_seconds: float = 0.02,
    fail_open_on_connect_error: bool = True,
        limiter: Optional[DNSRateLimiter] = None,
) -> Tuple[bool, Optional[ErrorCode]]:
    """Check DNS rebinding risk and return deterministic status.

    Args:
        host: Hostname or IP string to validate.
        timeout_seconds: Socket timeout in seconds; defaults to DEFAULT_DNS_TIMEOUT.
        enforce_rate_limit: Whether to enforce DNS rate limiting.
        retries: Number of retry attempts after the initial attempt.
        backoff_base_seconds: Base backoff duration for exponential backoff.
        backoff_jitter_seconds: Maximum jitter added to backoff.
        fail_open_on_connect_error: If True, treat transport/connect verification
            errors as safe (availability-first). If False, fail closed.
        limiter: Optional DNSRateLimiter instance. Prefer passing an explicit
            limiter for request/application isolation. If omitted and rate
            limiting is enabled, a process-global compatibility limiter is used.

    Returns:
        (is_safe, error_code) where error_code is None on success.
    """
    normalized_host = _validate_host(host)
    if normalized_host is None:
        return False, ErrorCode.DNS_RESOLUTION_FAILED

    effective_timeout_value = timeout_seconds if timeout_seconds is not None else timeout
    effective_timeout_seconds = DEFAULT_DNS_TIMEOUT if effective_timeout_value is None else effective_timeout_value
    if effective_timeout_seconds <= 0:
        return False, ErrorCode.DNS_CONNECTION_FAILED

    direct_result = _check_direct_ip_safe(normalized_host)
    if direct_result is not None:
        return direct_result, None if direct_result else ErrorCode.SSRF_RISK

    if enforce_rate_limit:
        effective_limiter = get_dns_rate_limiter() if limiter is None else limiter
        if not effective_limiter.is_allowed(normalized_host):
            logger.warning(
                "dns_check_blocked_rate_limit",
                extra={"event": "dns_check_blocked_rate_limit", "host": normalized_host},
            )
            return False, ErrorCode.DNS_RATE_LIMITED

    last_error: Optional[ErrorCode] = None
    max_attempts = max(1, retries + 1)

    for attempt_index in range(max_attempts):
        try:
            addr_info: AddrInfo = _resolve_addr_info(
                normalized_host, effective_timeout_seconds
            )
            if not _check_resolved_ips_safe(addr_info):
                return False, ErrorCode.SSRF_RISK
            if not _verify_connection_safe(
                addr_info,
                effective_timeout_seconds,
                fail_open_on_error=fail_open_on_connect_error,
            ):
                return False, ErrorCode.DNS_CONNECTION_FAILED
            return True, None
        except socket.gaierror:
            last_error = ErrorCode.DNS_RESOLUTION_FAILED
        except (socket.timeout, OSError):
            last_error = ErrorCode.DNS_CONNECTION_FAILED

        is_last_attempt = attempt_index + 1 >= max_attempts
        if not is_last_attempt:
            backoff_seconds = (backoff_base_seconds * (2 ** attempt_index)) + _secure_jitter_seconds(
                backoff_jitter_seconds
            )
            if backoff_seconds > 0:
                time.sleep(backoff_seconds)

    return False, last_error or ErrorCode.DNS_RESOLUTION_FAILED


def check_dns_rebinding(
    host: str,
    timeout_seconds: Optional[float] = None,
    timeout: Optional[float] = None,
    enforce_rate_limit: bool = True,
    retries: int = 2,
    backoff_base_seconds: float = 0.05,
    backoff_jitter_seconds: float = 0.02,
    fail_open_on_connect_error: bool = True,
    limiter: Optional[DNSRateLimiter] = None,
) -> bool:
    """Boolean wrapper around detailed DNS rebinding checks.

    Returns:
        True if host is considered safe, False otherwise.
    """
    is_safe, _ = check_dns_rebinding_detailed(
        host=host,
        timeout_seconds=timeout_seconds,
        timeout=timeout,
        enforce_rate_limit=enforce_rate_limit,
        retries=retries,
        backoff_base_seconds=backoff_base_seconds,
        backoff_jitter_seconds=backoff_jitter_seconds,
        fail_open_on_connect_error=fail_open_on_connect_error,
        limiter=limiter,
    )
    return is_safe


__all__ = [
    "DNSRateLimiter",
    "DNSRateLimiterConfig",
    "check_dns_rate_limit",
    "check_dns_rebinding",
    "check_dns_rebinding_detailed",
    "get_dns_rate_limiter",
    "reset_dns_rate_limiter",
]


