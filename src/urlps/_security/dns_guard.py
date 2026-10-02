"""Parse-time DNS checks: resolve a host and judge every address it resolves to.

Separate pieces, each injectable:

- :class:`DNSRateLimiter` -- how many lookups may reach the resolver;
- :class:`DNSResolutionCache` -- raw resolutions (not verdicts), so repeat
  checks of a host cost one lookup per TTL;
- the resolver and the clocks, passed to :func:`check_host_resolution`.

The process-global limiter and cache are the defaults; inject your own
through :class:`urlps.SecurityServices` (or a policy's ``dns_rate_limiter``).
"""

from __future__ import annotations

import logging
import secrets
import socket
import threading
import time
import warnings
from collections import OrderedDict, defaultdict, deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from typing import Any

from .._host import ip_literal_text
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
    IpFilter,
    _check_direct_ip_safe,
    _check_resolved_ips_safe,
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
    # Deprecated 1.2.0 cache settings; configure a DNSResolutionCache instead.
    # Removed in 2.0. As in 1.2.0, a limiter built with a non-default value
    # here keeps its own cache with these settings, and the DNS check uses it
    # for that limiter's lookups unless a resolution cache is injected -- so
    # cache_ttl_seconds=0 still turns caching off.
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
        if self._legacy_cache_config() is not None:
            warnings.warn(
                "DNSRateLimiterConfig(cache_ttl_seconds=, negative_cache_ttl_seconds=, max_cached_hosts=) "
                "is deprecated; pass SecurityServices(resolution_cache=DNSResolutionCache(DNSCacheConfig(...))) "
                "instead. It will be removed in 2.0.",
                DeprecationWarning,
                stacklevel=3,  # caller -> dataclass __init__ -> here
            )

    def _legacy_cache_config(self) -> DNSCacheConfig | None:
        """The cache the deprecated fields ask for, or None when they are all defaults."""
        settings = (self.cache_ttl_seconds, self.negative_cache_ttl_seconds, self.max_cached_hosts)
        defaults = (DEFAULT_DNS_CACHE_TTL_SECONDS, DEFAULT_DNS_NEGATIVE_CACHE_TTL_SECONDS, DEFAULT_DNS_MAX_CACHED_HOSTS)
        if settings == defaults:
            return None
        # DNSCacheConfig validates them (negative TTLs, max_cached_hosts <= 0).
        return DNSCacheConfig(*settings)


class DNSRateLimiter:
    """Token-bucket DNS rate limiter with per-host tracking.

    Only lookups that actually reach the resolver are charged; an answer
    from the :class:`DNSResolutionCache` is free. Inject one per tenant so
    one tenant cannot spend another's budget.

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
        legacy_cache_config = config._legacy_cache_config()
        # Only set for the deprecated DNSRateLimiterConfig cache fields.
        self._own_cache = (
            DNSResolutionCache(legacy_cache_config, time_provider) if legacy_cache_config is not None else None
        )

        now = self._time_provider()
        self._tokens: float = config.max_lookups_per_second
        self._last_update_seconds: float = now
        self._host_lookups: dict[str, deque[float]] = defaultdict(deque)
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

    def reset(self) -> None:
        """Reset limiter state to its initial configuration (and its own cache, if it has one)."""
        with self._lock:
            now = self._now()
            self._tokens = self._config.max_lookups_per_second
            self._last_update_seconds = now
            self._host_lookups.clear()
            self._last_cleanup_seconds = now
        if self._own_cache is not None:
            self._own_cache.reset()

    def stats(self) -> dict[str, float]:
        """Return current limiter statistics.

        Takes the lock so the snapshot is internally consistent rather than
        read while another thread is mid-update.
        """
        with self._lock:
            self._refill_tokens()
            total_recent_lookups = sum(len(timestamps) for timestamps in self._host_lookups.values())
            stats = {
                "tokens": float(self._tokens),
                "tracked_hosts": float(len(self._host_lookups)),
                "total_recent_lookups": float(total_recent_lookups),
            }
        # 1.2.0 reported its cache here; keep the key.
        stats.update(self._compat_cache().stats())
        return stats

    # -- Deprecated 1.2.0 cache API (removed in 2.0) -----------------------

    def _compat_cache(self) -> DNSResolutionCache:
        """The cache this limiter's lookups use when none is injected."""
        return self._own_cache if self._own_cache is not None else get_resolution_cache()

    def cached_resolution(self, host: str) -> CachedResolution | None:
        """Deprecated: use :meth:`DNSResolutionCache.get`. Removed in 2.0."""
        _warn_cache_method("cached_resolution", "get")
        return self._compat_cache().get(host)

    def store_resolution(self, host: str, addr_info: AddrInfo | None, error: ErrorCode | None = None) -> None:
        """Deprecated: use :meth:`DNSResolutionCache.store`. Removed in 2.0."""
        _warn_cache_method("store_resolution", "store")
        self._compat_cache().store(host, addr_info, error)


def _warn_cache_method(name: str, replacement: str) -> None:
    warnings.warn(
        f"DNSRateLimiter.{name}() is deprecated; the resolution cache is separate from the limiter now. "
        f"Use DNSResolutionCache.{replacement}() (the process-global one is get_resolution_cache()). "
        "It will be removed in 2.0.",
        DeprecationWarning,
        stacklevel=3,
    )


@dataclass(frozen=True)
class DNSCacheConfig:
    """Configuration for :class:`DNSResolutionCache`.

    Checking the same host repeatedly costs one lookup per TTL rather than
    one per check; without it the per-host limit rejected the 4th legitimate
    check of a host within a minute, and anyone could lock a host out by
    submitting it three times. The parse-time check is advisory either way
    (create_guarded_connection gives the connect-time guarantee), so caching
    a positive answer briefly costs no protection. A TTL of 0 disables that
    half of the cache.
    """

    ttl_seconds: float = DEFAULT_DNS_CACHE_TTL_SECONDS
    negative_ttl_seconds: float = DEFAULT_DNS_NEGATIVE_CACHE_TTL_SECONDS
    max_hosts: int = DEFAULT_DNS_MAX_CACHED_HOSTS

    def __post_init__(self) -> None:
        if self.ttl_seconds < 0 or self.negative_ttl_seconds < 0:
            raise DNSRateLimiterError("cache TTLs must not be negative")
        if self.max_hosts <= 0:
            raise DNSRateLimiterError("max_hosts must be positive")


@dataclass(frozen=True)
class CachedResolution:
    """A cached answer: the address info, or the error a lookup ended with."""

    expires_at: float
    addr_info: tuple[tuple[int, int, int, str, tuple], ...] | None
    error: ErrorCode | None


class DNSResolutionCache:
    """Bounded, thread-safe cache of raw resolutions, keyed by host.

    It holds what the resolver said, not a verdict, so each policy still
    applies its own address rules to a cached answer -- which is also why
    one cache can be shared by tenants with different policies.
    """

    def __init__(self, config: DNSCacheConfig | None = None, time_provider: TimeProvider = time.time) -> None:
        self._config = config if config is not None else DNSCacheConfig()
        self._now = time_provider
        self._entries: OrderedDict[str, CachedResolution] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def config(self) -> DNSCacheConfig:
        return self._config

    def get(self, host: str) -> CachedResolution | None:
        """The unexpired cached resolution for ``host``, if any."""
        with self._lock:
            entry = self._entries.get(host)
            if entry is None:
                return None
            if entry.expires_at <= self._now():
                del self._entries[host]
                return None
            self._entries.move_to_end(host)
            return entry

    def store(self, host: str, addr_info: AddrInfo | None, error: ErrorCode | None = None) -> None:
        """Cache a successful resolution, or a failed one (``addr_info=None``)."""
        ttl = self._config.ttl_seconds if addr_info is not None else self._config.negative_ttl_seconds
        if ttl <= 0:
            return
        with self._lock:
            self._entries[host] = CachedResolution(
                expires_at=self._now() + ttl,
                addr_info=tuple(addr_info) if addr_info is not None else None,
                error=error,
            )
            self._entries.move_to_end(host)
            while len(self._entries) > self._config.max_hosts:
                self._entries.popitem(last=False)

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()

    def stats(self) -> dict[str, float]:
        with self._lock:
            return {"cached_hosts": float(len(self._entries))}


@dataclass(frozen=True)
class DNSCheckOptions:
    """How hard one parse-time DNS check tries (see ``SecurityPolicy.dns_options``)."""

    timeout_seconds: float = DEFAULT_DNS_TIMEOUT
    retries: int = 2
    backoff_base_seconds: float = 0.05
    backoff_jitter_seconds: float = 0.02
    #: Wall-clock bound across all attempts and backoff.
    deadline_seconds: float = DEFAULT_DNS_DEADLINE_SECONDS
    enforce_rate_limit: bool = True


@dataclass(frozen=True)
class DNSCheckResult:
    """The outcome of a DNS check: no error means every address was permitted."""

    error: ErrorCode | None = None
    #: For ``DNS_RATE_LIMITED``: seconds until a lookup would be allowed.
    retry_after: float | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


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
    return ip_literal_text(stripped)


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
    """Reset the process-global DNS rate limiter, and the process-global resolution cache.

    Compatibility API for integrations still using the process-global limiter.
    The cache is reset too because in 1.2.0 it belonged to this limiter, so
    a reset between tests also forgot every cached answer.
    """
    get_dns_rate_limiter().reset()
    reset_resolution_cache()


_GLOBAL_RESOLUTION_CACHE = DNSResolutionCache()


def get_resolution_cache() -> DNSResolutionCache:
    """The process-global resolution cache, used when none is injected."""
    return _GLOBAL_RESOLUTION_CACHE


def reset_resolution_cache() -> None:
    """Forget every cached resolution in the process-global cache."""
    _GLOBAL_RESOLUTION_CACHE.reset()


#: (host, timeout_seconds, port) -> getaddrinfo-style address info.
Resolver = Callable[..., AddrInfo]


def default_resolver(host: str, timeout_seconds: float | None = None, port: int = 80) -> AddrInfo:
    """``getaddrinfo`` with a timeout (see :func:`_resolve_addr_info`).

    Looks the implementation up at call time, so substituting
    ``_resolve_addr_info`` (as the test suite does) still takes effect.
    """
    return _resolve_addr_info(host, timeout_seconds, port=port)


def _monotonic() -> float:
    return time.monotonic()


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


def check_host_resolution(
    host: str,
    options: DNSCheckOptions = DNSCheckOptions(),
    *,
    ip_filter: IpFilter | None = None,
    limiter: DNSRateLimiter | None = None,
    cache: DNSResolutionCache | None = None,
    resolver: Resolver = default_resolver,
    clock: TimeProvider = _monotonic,
    sleep: Callable[[float], None] = _sleep,
) -> DNSCheckResult:
    """Check that ``host`` currently resolves only to addresses ``ip_filter`` permits.

    This is a parse-time check: it rejects hosts that resolve to internal
    addresses *now*. It cannot prevent DNS rebinding, because the HTTP client
    resolves the name again when it connects; use
    :func:`urlps.create_guarded_connection` or
    :func:`urlps.resolve_and_validate` for that.

    Args:
        host: Hostname or IP literal (an IPv6 literal may be bracketed).
        options: Timeout, retries, backoff, total deadline, and whether to
            rate limit.
        ip_filter: Whether an address is acceptable; defaults to the built-in
            public-unicast classification. The security checks pass the
            policy's, so its address rules apply here too.
        limiter: Rate limiter charged for real lookups; defaults to the
            process-global one when ``options.enforce_rate_limit``.
        cache: Resolution cache; defaults to the process-global one. A cached
            answer is used without a lookup and without spending budget.
        resolver: ``(host, timeout_seconds, port=80) -> address info``.
        clock, sleep: Monotonic clock and sleep for the deadline and backoff.
    """
    normalized_host = _validate_host(host)
    if normalized_host is None:
        return DNSCheckResult(ErrorCode.DNS_RESOLUTION_FAILED)
    if options.timeout_seconds <= 0:
        return DNSCheckResult(ErrorCode.DNS_CONNECTION_FAILED)

    direct_result = _check_direct_ip_safe(normalized_host, ip_filter)
    if direct_result is not None:
        return DNSCheckResult(None if direct_result else ErrorCode.SSRF_RISK)

    if cache is not None:
        effective_cache = cache
    elif limiter is not None and limiter._own_cache is not None:
        effective_cache = limiter._own_cache  # deprecated 1.2.0 limiter cache settings
    else:
        effective_cache = get_resolution_cache()
    cached = effective_cache.get(normalized_host)
    if cached is not None:
        if cached.addr_info is None:
            return DNSCheckResult(cached.error or ErrorCode.DNS_RESOLUTION_FAILED)
        return DNSCheckResult(None if _check_resolved_ips_safe(cached.addr_info, ip_filter) else ErrorCode.SSRF_RISK)

    effective_limiter = (
        limiter if limiter is not None else (get_dns_rate_limiter() if options.enforce_rate_limit else None)
    )
    if (
        options.enforce_rate_limit
        and effective_limiter is not None
        and not effective_limiter.is_allowed(normalized_host)
    ):
        logger.warning(
            "dns_check_blocked_rate_limit",
            extra={"event": "dns_check_blocked_rate_limit", "host": normalized_host},
        )
        return DNSCheckResult(ErrorCode.DNS_RATE_LIMITED, retry_after=effective_limiter.retry_after(normalized_host))

    budget = max(0.0, options.deadline_seconds)
    deadline = clock() + budget
    last_error: ErrorCode | None = None
    max_attempts = max(1, options.retries + 1)

    for attempt_index in range(max_attempts):
        # Clamp to the budget: on a coarse clock (Windows) the float
        # arithmetic can otherwise hand the first attempt budget + epsilon.
        remaining = min(budget, deadline - clock())
        if remaining <= 0:
            last_error = last_error or ErrorCode.DNS_CONNECTION_FAILED
            break
        try:
            addr_info: AddrInfo = resolver(normalized_host, min(options.timeout_seconds, remaining))
        except socket.gaierror:
            last_error = ErrorCode.DNS_RESOLUTION_FAILED
        except (TimeoutError, OSError):
            last_error = ErrorCode.DNS_CONNECTION_FAILED
        else:
            effective_cache.store(normalized_host, addr_info)
            return DNSCheckResult(None if _check_resolved_ips_safe(addr_info, ip_filter) else ErrorCode.SSRF_RISK)

        if attempt_index + 1 < max_attempts:
            backoff_seconds = (options.backoff_base_seconds * (2**attempt_index)) + _secure_jitter_seconds(
                options.backoff_jitter_seconds
            )
            backoff_seconds = min(backoff_seconds, max(0.0, deadline - clock()))
            if backoff_seconds > 0:
                sleep(backoff_seconds)

    if last_error == ErrorCode.DNS_RESOLUTION_FAILED:
        # Timeouts are not cached: they are transient, and caching one would
        # turn a brief resolver hiccup into a TTL-long outage for the host.
        effective_cache.store(normalized_host, None, ErrorCode.DNS_RESOLUTION_FAILED)
    return DNSCheckResult(last_error or ErrorCode.DNS_RESOLUTION_FAILED)


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
    ip_filter: IpFilter | None = None,
    deadline_seconds: float | None = None,
) -> tuple[bool, ErrorCode | None]:
    """Compatibility form of :func:`check_host_resolution`: ``(is_safe, error_code)``.

    ``timeout`` is an alias of ``timeout_seconds``; ``fail_open_on_connect_error``
    is deprecated and ignored (it governed a removed "verification connect").
    """
    effective_timeout = timeout_seconds if timeout_seconds is not None else timeout
    result = check_host_resolution(
        host,
        DNSCheckOptions(
            timeout_seconds=DEFAULT_DNS_TIMEOUT if effective_timeout is None else effective_timeout,
            retries=retries,
            backoff_base_seconds=backoff_base_seconds,
            backoff_jitter_seconds=backoff_jitter_seconds,
            deadline_seconds=DEFAULT_DNS_DEADLINE_SECONDS if deadline_seconds is None else deadline_seconds,
            enforce_rate_limit=enforce_rate_limit,
        ),
        ip_filter=ip_filter,
        limiter=limiter,
    )
    return result.ok, result.error


def check_dns_rebinding(host: str, *args: Any, **kwargs: Any) -> bool:
    """Boolean form of :func:`check_dns_rebinding_detailed` (same arguments)."""
    is_safe, _ = check_dns_rebinding_detailed(host, *args, **kwargs)
    return is_safe


__all__ = [
    "CachedResolution",
    "DNSCacheConfig",
    "DNSCheckOptions",
    "DNSCheckResult",
    "DNSRateLimiter",
    "DNSRateLimiterConfig",
    "DNSResolutionCache",
    "Resolver",
    "check_dns_rate_limit",
    "check_dns_rebinding",
    "check_dns_rebinding_detailed",
    "check_host_resolution",
    "default_resolver",
    "get_dns_rate_limiter",
    "get_resolution_cache",
    "reset_dns_rate_limiter",
    "reset_resolution_cache",
]
