"""Pytest test configuration for import paths."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


def _ensure_src_on_path() -> None:
    """Add repository paths so `urlps` and legacy `urlps` imports both resolve."""
    repo_root = Path(__file__).resolve().parents[1]
    src_dir = repo_root / "src"
    repo_root_str = str(repo_root)
    src_dir_str = str(src_dir)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)
    if src_dir_str not in sys.path:
        sys.path.insert(0, src_dir_str)


_ensure_src_on_path()


@pytest.fixture(autouse=True)
def _fresh_global_dns_state():
    """The process-global DNS limiter and resolution cache; never share them between tests."""
    from urlps._security.dns_guard import reset_dns_rate_limiter, reset_resolution_cache

    reset_dns_rate_limiter()
    reset_resolution_cache()
    yield
    reset_dns_rate_limiter()
    reset_resolution_cache()


class FakeResolver:
    """A resolver for SecurityServices: records each host, answers with one address or raises."""

    def __init__(self, address: str = "93.184.216.34", error: BaseException | None = None) -> None:
        self.address = address
        self.error = error
        self.calls: list[str] = []

    def __call__(self, host: str, timeout_seconds: float | None = None, port: int = 80) -> list[tuple]:
        import socket

        self.calls.append(host)
        if self.error is not None:
            raise self.error
        family = socket.AF_INET6 if ":" in self.address else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 6, "", (self.address, port))]


class FakeFeed:
    """A PhishingFeed: ``listed`` hosts are phishing; ``available=False`` means nothing can be checked."""

    def __init__(self, listed: tuple[str, ...] = (), available: bool = True) -> None:
        self.listed = set(listed)
        self.available = available
        self.calls: list[str] = []

    def lookup(self, host: str) -> bool | None:
        self.calls.append(host)
        if not self.available:
            return None
        return host in self.listed


def make_services(resolver=None, feed=None, limiter=None):
    """SecurityServices over fakes, with caching off so every check reaches them."""
    from urlps import DNSCacheConfig, DNSResolutionCache, SecurityServices

    return SecurityServices(
        resolver=resolver if resolver is not None else FakeResolver(),
        phishing_feed=feed,
        dns_rate_limiter=limiter,
        resolution_cache=DNSResolutionCache(DNSCacheConfig(ttl_seconds=0, negative_ttl_seconds=0)),
    )


@pytest.fixture
def fakes():
    """Test doubles for the security checks' I/O, injected through SecurityServices."""
    from types import SimpleNamespace

    return SimpleNamespace(Resolver=FakeResolver, Feed=FakeFeed, services=make_services)
