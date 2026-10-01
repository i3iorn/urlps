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
from collections import OrderedDict, defaultdict, deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass

from ..constants import (
    DEFAULT_DNS_CACHE_TTL_SECONDS,
    DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS,
    DEFAULT_DNS_DEADLINE_SECONDS,
    DEFAULT_DNS_LOOKUPS_PER_HOST,
    DEFAULT_DNS_LOOKUPS_PER_SECOND,
    DEFAULT_DNS_MAX_CACHED_HOSTS,
    DEFAULT_DNS_NEGATIVE_CACHE_TTL_SECONDS,
    DEFAULT_DNS_TIME_WINDOW_SECONDS,
    DEFAULT_DNS_TIMEOUT,
)
from ..exceptions import DNSRateLimiterError, ErrorCode
from .ip_utils import (
    AddrInfo,
    IpAddress,
    _check_direct_ip_safe,
    _check_resolved_ips_safe,
    _strip_ipv6_brackets,
)

logger = logging.getLogger(__name__)
_GLOBAL_RATE_LIMITER: DNSRateLimiter | None = None
_GLOBAL_RATE_LIMITER_LOCK = threading.Lock()


TimeProvider = Callable[[], float]


@dataclass(frozen=True)
class DNSRateLimiterConfig:
    """Configuration for DNSRateLimiter."""

    max_lookups_per_second: float = DEFAULT_DNS_LOOKUPS_PER_SECOND
    max_lookups_per_host: int = DEFAULT_DNS_LOOKUPS_PER_HOST
    time_window_seconds: float = DEFAULT_DNS_TIME_WINDOW_SECONDS
    cleanup_interval_seconds: float = DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS
    # Resolutions are cached so that checking the same host repeatedly costs
    # one lookup per TTL rather than one per check. Without this, the
    # per-host limit rejected the 4th legitimate check of a host within a
    # minute, and anyone could lock a host out by submitting it 3 times.
    # 0 disables a cache. The parse-time check is advisory either way (see
    # create_guarded_connection for the connect-time guarantee), so caching a
    # positive answer briefly costs no protection.
    cache_ttl_seconds: float = DEFAULT_DNS_CACHE_TTL_SECONDS
    negative_cache_ttl_seconds: float = DEFAULT_DNS_NEGATIVE_CACHE_TTL_SECONDS
    max_cached_hosts: int = DEFAULT_DNS_MAX_CACHED_HOSTS

    def __post_init__(self):
        if self.max_lookups_per_second <= 0:
            raise DNSRateLimiterError("max_lookups_per_second must be positive")
        if self.max_lookups_per_host <= 0:
            raise DNSRateLimiterError("max_lookups_per_host must be positive")
        if self.time_window_seconds <= 0:
            raise DNSRateLimiterError("time_window_seconds must be positive")
        if self.cleanup_interval_seconds <= 0:
            raise DNSRateLimiterError("cleanup_interval_seconds must be positive")
        if self.cache_ttl_seconds < 0 or self.negative_cache_ttl_seconds < 0:
            raise DNSRateLimiterError("cache TTLs must not be negative")
        if self.max_cached_hosts <= 0:
            raise DNSRateLimiterError("max_cached_hosts must be positive")


@dataclass(frozen=True)
class _CachedResolution:
    expires_at: float
    addr_info: tuple[tuple[int, int, int, str, tuple], ...] | None
    error: ErrorCode | None


class DNSRateLimiter:
    """Token-bucket DNS rate limiter with per-host tracking and a resolution cache.

    Only lookups that actually reach the resolver are rate limited; a cached
    answer is free. The cache holds raw resolutions, not verdicts, so each
    policy still applies its own address rules to a cached answer.

    The limiter is deterministic, side-effect free outside its own state,
    and uses an injected time provider for testability.
    """

    def __init__(
        self,
        config: DNSRateLimiterConfig | None = None,
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
        self._host_lookups: dict[str, deque[float]] = defaultdict(deque)
        self._last_cleanup_seconds: float = now
        self._cache: OrderedDict[str, _CachedResolution] = OrderedDict()
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

    def _remove_stale_timestamps(self, timestamps: deque[float], cutoff_seconds: float) -> None:
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

    def retry_after(self, host: str) -> float:
        """Seconds until a lookup for ``host`` would no longer be rate limited."""
        with self._lock:
            self._refill_tokens()
            now = self._now()
            wait = 0.0
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._config.max_lookups_per_second
            timestamps = self._host_lookups.get(host)
            if timestamps and len(timestamps) >= self._config.max_lookups_per_host:
                wait = max(wait, timestamps[0] + self._config.time_window_seconds - now)
            return max(0.0, wait)

    def cached_resolution(self, host: str) -> _CachedResolution | None:
        """Return the unexpired cached resolution for ``host``, if any."""
        with self._lock:
            entry = self._cache.get(host)
            if entry is None:
                return None
            if entry.expires_at <= self._now():
                del self._cache[host]
                return None
            self._cache.move_to_end(host)
            return entry

    def store_resolution(
        self,
        host: str,
        addr_info: AddrInfo | None,
        error: ErrorCode | None = None,
    ) -> None:
        """Cache a successful resolution, or a failed one (``addr_info=None``)."""
        ttl = self._config.cache_ttl_seconds if addr_info is not None else self._config.negative_cache_ttl_seconds
        if ttl <= 0:
            return
        with self._lock:
            self._cache[host] = _CachedResolution(
                expires_at=self._now() + ttl,
                addr_info=tuple(addr_info) if addr_info is not None else None,
                error=error,
            )
            self._cache.move_to_end(host)
            while len(self._cache) > self._config.max_cached_hosts:
                self._cache.popitem(last=False)

    def reset(self) -> None:
        """Reset limiter state, including the resolution cache, to initial configuration."""
        with self._lock:
            now = self._now()
            self._tokens = self._config.max_lookups_per_second
            self._last_update_seconds = now
            self._host_lookups.clear()
            self._last_cleanup_seconds = now
            self._cache.clear()

    def stats(self) -> dict[str, float]:
        """Return current limiter statistics.

        Takes the lock so the snapshot is internally consistent rather than
        read while another thread is mid-update.
        """
        with self._lock:
            self._refill_tokens()
            total_recent_lookups = sum(len(timestamps) for timestamps in self._host_lookups.values())
            return {
                "tokens": float(self._tokens),
                "tracked_hosts": float(len(self._host_lookups)),
                "total_recent_lookups": float(total_recent_lookups),
                "cached_hosts": float(len(self._cache)),
            }


def _secure_jitter_seconds(max_jitter_seconds: float) -> float:
    """Return cryptographically strong jitter in [0, max_jitter_seconds]."""
    if max_jitter_seconds <= 0:
        return 0.0

    scale = 1_000_000
    random_int = secrets.randbelow(scale + 1)
    jitter_fraction = random_int / scale
    return jitter_fraction * max_jitter_seconds


def _validate_host(host: str) -> str | None:
    """Return a normalized host or None if invalid."""
    if not isinstance(host, str):
        return None
    stripped = host.strip()
    if not stripped:
        return None
    return _strip_ipv6_brackets(stripped)


def _resolve_addr_info(
    host: str, timeout_seconds: float | None = None, port: int = 80
) -> list[tuple[int, int, int, str, tuple]]:
    """Resolve host to address info, raising socket.gaierror on failure.

    ``socket.getaddrinfo`` takes no timeout argument and is bounded only by the
    OS resolver, which under packet loss can block for 5-30 seconds --
    unaffected by ``socket.setdefaulttimeout``. To honor ``timeout_seconds``
    for the lookup itself (not just the subsequent socket connect), the
    lookup runs in a worker thread and is abandoned on timeout; the abandoned
    thread is a daemon and finishes on its own.

    Deliberately a fresh ``ThreadPoolExecutor`` per call, not a shared
    module-level pool -- this was profiled (2000 calls, mocked
    ``getaddrinfo``): a fresh pool costs ~280us/call versus ~60us/call
    reusing one, so the churn is real but small, and it stays that way
    only because the alternative has a worse failure mode. A shared pool
    with N workers permanently loses a worker to any resolution that
    hangs forever rather than erroring or timing out -- which is exactly
    the kind of adversarial-DNS behavior this module has to assume it
    might face -- so N such hangs over the process lifetime silently
    exhausts it and DNS lookups start queuing (and eventually timing out)
    even when the network is fine. A fresh executor per call is
    self-healing: an abandoned worker thread costs nothing beyond itself.
    The ~220us/call difference is well under real DNS resolution latency
    (typically single-digit milliseconds or worse), so it is not worth
    trading that durability for.
    """

    # The port only shapes the returned sockaddrs; resolution ignores it.
    def _lookup() -> list[tuple[int, int, int, str, tuple]]:
        return list(socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM))

    if timeout_seconds is None or timeout_seconds <= 0:
        return _lookup()

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="urlps-dns")
    try:
        future = executor.submit(_lookup)
        try:
            return future.result(timeout=timeout_seconds)
        except FuturesTimeoutError as exc:
            raise TimeoutError(f"DNS resolution for {host!r} exceeded {timeout_seconds}s") from exc
    finally:
        # Do not block on an in-flight lookup we have already given up on.
        executor.shutdown(wait=False)


def check_dns_rate_limit(host: str, limiter: DNSRateLimiter | None = None) -> bool:
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
    timeout_seconds: float | None = None,
    timeout: float | None = None,
    enforce_rate_limit: bool = True,
    retries: int = 2,
    backoff_base_seconds: float = 0.05,
    backoff_jitter_seconds: float = 0.02,
    fail_open_on_connect_error: bool = True,
    limiter: DNSRateLimiter | None = None,
    ip_filter: Callable[[IpAddress], bool] | None = None,
    deadline_seconds: float | None = None,
) -> tuple[bool, ErrorCode | None]:
    """Check that ``host`` currently resolves only to permitted addresses.

    This is a parse-time check: it rejects hosts that resolve to internal
    addresses *now*. It cannot prevent DNS rebinding, because the HTTP client
    resolves the name again when it connects; use
    :func:`urlps.create_guarded_connection` or
    :func:`urlps.resolve_and_validate` for that.

    Args:
        host: Hostname or IP string to validate.
        timeout_seconds: Socket timeout in seconds; defaults to DEFAULT_DNS_TIMEOUT.
        enforce_rate_limit: Whether to enforce DNS rate limiting.
        retries: Number of retry attempts after the initial attempt.
        backoff_base_seconds: Base backoff duration for exponential backoff.
        backoff_jitter_seconds: Maximum jitter added to backoff.
        fail_open_on_connect_error: Deprecated and ignored. It governed a
            post-resolution "verification connect" that re-checked the address
            just resolved -- it could not detect rebinding (the HTTP client
            resolves again later) and only added an outbound connection to an
            attacker-chosen host. Use urlps.create_guarded_connection() for
            protection at connect time.
        limiter: Optional DNSRateLimiter instance. Prefer passing an explicit
            limiter for request/application isolation. If omitted and rate
            limiting is enabled, a process-global compatibility limiter is used.
        ip_filter: Decides whether an address is acceptable; defaults to the
            built-in public-unicast classification. ``collect_security_findings``
            passes the policy's, so allowed/denied address rules apply here too.
        deadline_seconds: Wall-clock bound across all attempts and backoff;
            defaults to DEFAULT_DNS_DEADLINE_SECONDS.

    The limiter (the injected one, or the process-global one when rate
    limiting is on) also caches resolutions: a cached answer is used without
    a lookup and without spending rate-limit budget.

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

    direct_result = _check_direct_ip_safe(normalized_host, ip_filter)
    if direct_result is not None:
        return direct_result, None if direct_result else ErrorCode.SSRF_RISK

    effective_limiter = limiter if limiter is not None else (get_dns_rate_limiter() if enforce_rate_limit else None)
    if effective_limiter is not None:
        cached = effective_limiter.cached_resolution(normalized_host)
        if cached is not None:
            if cached.addr_info is None:
                return False, cached.error or ErrorCode.DNS_RESOLUTION_FAILED
            if not _check_resolved_ips_safe(cached.addr_info, ip_filter):
                return False, ErrorCode.SSRF_RISK
            return True, None

    if enforce_rate_limit and effective_limiter is not None and not effective_limiter.is_allowed(normalized_host):
        logger.warning(
            "dns_check_blocked_rate_limit",
            extra={"event": "dns_check_blocked_rate_limit", "host": normalized_host},
        )
        return False, ErrorCode.DNS_RATE_LIMITED

    effective_deadline = DEFAULT_DNS_DEADLINE_SECONDS if deadline_seconds is None else deadline_seconds
    deadline = time.monotonic() + max(0.0, effective_deadline)
    last_error: ErrorCode | None = None
    max_attempts = max(1, retries + 1)

    for attempt_index in range(max_attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last_error = last_error or ErrorCode.DNS_CONNECTION_FAILED
            break
        try:
            addr_info: AddrInfo = _resolve_addr_info(normalized_host, min(effective_timeout_seconds, remaining))
        except socket.gaierror:
            last_error = ErrorCode.DNS_RESOLUTION_FAILED
        except (TimeoutError, OSError):
            last_error = ErrorCode.DNS_CONNECTION_FAILED
        else:
            if effective_limiter is not None:
                effective_limiter.store_resolution(normalized_host, addr_info)
            if not _check_resolved_ips_safe(addr_info, ip_filter):
                return False, ErrorCode.SSRF_RISK
            return True, None

        is_last_attempt = attempt_index + 1 >= max_attempts
        if not is_last_attempt:
            backoff_seconds = (backoff_base_seconds * (2**attempt_index)) + _secure_jitter_seconds(
                backoff_jitter_seconds
            )
            backoff_seconds = min(backoff_seconds, max(0.0, deadline - time.monotonic()))
            if backoff_seconds > 0:
                time.sleep(backoff_seconds)

    if last_error == ErrorCode.DNS_RESOLUTION_FAILED and effective_limiter is not None:
        # Timeouts are not cached: they are transient, and caching one would
        # turn a brief resolver hiccup into a TTL-long outage for the host.
        effective_limiter.store_resolution(normalized_host, None, ErrorCode.DNS_RESOLUTION_FAILED)
    return False, last_error or ErrorCode.DNS_RESOLUTION_FAILED


def check_dns_rebinding(
    host: str,
    timeout_seconds: float | None = None,
    timeout: float | None = None,
    enforce_rate_limit: bool = True,
    retries: int = 2,
    backoff_base_seconds: float = 0.05,
    backoff_jitter_seconds: float = 0.02,
    fail_open_on_connect_error: bool = True,
    limiter: DNSRateLimiter | None = None,
    ip_filter: Callable[[IpAddress], bool] | None = None,
    deadline_seconds: float | None = None,
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
        ip_filter=ip_filter,
        deadline_seconds=deadline_seconds,
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
