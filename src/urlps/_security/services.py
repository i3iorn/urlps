"""The I/O the security checks depend on, injectable as one value.

``SecurityServices`` bundles the resolver, the resolution cache, the DNS
rate limiter and the phishing feed. Every entry point takes ``services=``;
the default uses the process-global cache, limiter and feed, which is what
urlps always did. Inject your own to give a tenant its own budget and feed,
to point the phishing check at a mirror, or to test without network access::

    services = SecurityServices(resolver=my_resolver, phishing_feed=my_feed)
    parse_url(url, policy=SecurityPolicy.strict(check_dns=True), services=services)
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .dns_guard import DNSRateLimiter, DNSResolutionCache, Resolver, default_resolver
from .phishing_db import default_phishing_feed

__all__ = ["DEFAULT_SERVICES", "PhishingFeed", "Resolver", "SecurityServices"]


class PhishingFeed(Protocol):
    """A source of known phishing hosts."""

    def lookup(self, host: str) -> bool | None:
        """True if ``host`` is listed, False if not, None if nothing could be checked (feed unavailable)."""
        ...


def _monotonic() -> float:
    # Looked up at call time, so substituting time.monotonic still takes effect.
    return time.monotonic()


def _sleep(seconds: float) -> None:
    time.sleep(seconds)


@dataclass(frozen=True)
class SecurityServices:
    """Resolver, caches, limiter, feed and clocks for the security checks.

    ``None`` for the cache, limiter or feed means the process-global one.
    The limiter here takes precedence over a policy's ``dns_rate_limiter``.
    """

    resolver: Resolver = default_resolver
    resolution_cache: DNSResolutionCache | None = None
    dns_rate_limiter: DNSRateLimiter | None = None
    phishing_feed: PhishingFeed | None = None
    clock: Callable[[], float] = _monotonic
    sleep: Callable[[float], None] = _sleep

    def feed(self) -> PhishingFeed:
        """The phishing feed to consult."""
        return self.phishing_feed if self.phishing_feed is not None else default_phishing_feed()


#: What every entry point uses unless given ``services=``.
DEFAULT_SERVICES = SecurityServices()
