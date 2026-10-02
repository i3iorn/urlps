"""1.2.0 APIs that 1.3 replaced, kept working (with a DeprecationWarning) until 2.0.

1.2.0 put the resolution cache inside DNSRateLimiter and named the address
rule ``ip_is_permitted``. 1.3 split the cache out and made
``permits_address`` the one rule, but code written against 1.2.0 must keep
meaning what it meant.
"""

from __future__ import annotations

import ipaddress
import warnings

import pytest

from urlps import (
    DNSRateLimiter,
    DNSRateLimiterConfig,
    DNSRateLimiterError,
    SecurityPolicy,
    SecurityServices,
    parse_url,
)
from urlps._security.dns_guard import get_resolution_cache, reset_dns_rate_limiter
from urlps.constants import DEFAULT_DNS_CACHE_TTL_SECONDS

PUBLIC = ipaddress.ip_address("93.184.216.34")
LOOPBACK = ipaddress.ip_address("127.0.0.1")
PRIVATE = ipaddress.ip_address("10.0.0.1")
METADATA = ipaddress.ip_address("169.254.169.254")


# -- SecurityPolicy.ip_is_permitted -----------------------------------------


def _ip_is_permitted(policy: SecurityPolicy, ip, **kwargs) -> bool:
    with pytest.warns(DeprecationWarning, match="ip_is_permitted"):
        return policy.ip_is_permitted(ip, **kwargs)


def test_ip_is_permitted_keeps_its_1_2_meaning() -> None:
    strict = SecurityPolicy.strict()
    assert _ip_is_permitted(strict, PUBLIC)
    assert not _ip_is_permitted(strict, LOOPBACK)
    # allow_private is the argument, not the policy field.
    assert _ip_is_permitted(strict, PRIVATE, allow_private=True)
    assert not _ip_is_permitted(strict, METADATA, allow_private=True)
    assert not _ip_is_permitted(SecurityPolicy.local(), PRIVATE)
    # A host allowed by name trusts its addresses, except metadata.
    assert _ip_is_permitted(strict, PRIVATE, host_allowed_by_name=True)
    assert not _ip_is_permitted(strict, METADATA, host_allowed_by_name=True)


def test_ip_is_permitted_applies_the_classification_even_with_enforce_ssrf_off() -> None:
    """The one place it differs from permits_address, as it did in 1.2.0."""
    policy = SecurityPolicy("custom", enforce_ssrf=False)
    assert policy.permits_address(LOOPBACK)
    assert not _ip_is_permitted(policy, LOOPBACK)


def test_ip_is_permitted_honours_address_rules() -> None:
    policy = SecurityPolicy.strict(allowed_addresses=["127.0.0.1"], denied_addresses=["93.184.216.34"])
    assert _ip_is_permitted(policy, LOOPBACK)
    assert not _ip_is_permitted(policy, PUBLIC)


# -- DNSRateLimiterConfig cache fields --------------------------------------


def test_default_limiter_config_does_not_warn_and_reads_like_1_2() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        config = DNSRateLimiterConfig()
        DNSRateLimiter(config)
    assert config.cache_ttl_seconds == DEFAULT_DNS_CACHE_TTL_SECONDS


def test_cache_fields_are_positional_in_their_1_2_order() -> None:
    with pytest.warns(DeprecationWarning, match="DNSRateLimiterConfig"):
        config = DNSRateLimiterConfig(10, 3, 60, 300, 0, 0, 7)
    assert (config.cache_ttl_seconds, config.negative_cache_ttl_seconds, config.max_cached_hosts) == (0, 0, 7)


@pytest.mark.parametrize(
    "kwargs", [{"cache_ttl_seconds": -1}, {"negative_cache_ttl_seconds": -1}, {"max_cached_hosts": 0}]
)
def test_invalid_cache_fields_still_fail_at_construction(kwargs) -> None:
    with pytest.raises(DNSRateLimiterError):
        DNSRateLimiterConfig(**kwargs)


def _limiter(**cache_fields) -> DNSRateLimiter:
    with pytest.warns(DeprecationWarning):
        return DNSRateLimiter(DNSRateLimiterConfig(max_lookups_per_host=100, **cache_fields))


def test_cache_ttl_zero_on_the_limiter_still_turns_caching_off(fakes) -> None:
    """The 1.2.0 way to disable caching must not silently start caching again."""
    resolver = fakes.Resolver()
    services = SecurityServices(resolver=resolver, dns_rate_limiter=_limiter(cache_ttl_seconds=0))
    for _ in range(3):
        parse_url("https://example.com/", check_dns=True, services=services)
    assert resolver.calls == ["example.com"] * 3


def test_limiter_cache_settings_apply_through_the_policy_too(fakes) -> None:
    resolver = fakes.Resolver()
    policy = SecurityPolicy.strict(check_dns=True, dns_rate_limiter=_limiter(cache_ttl_seconds=0))
    for _ in range(2):
        parse_url("https://example.com/", policy=policy, services=SecurityServices(resolver=resolver))
    assert resolver.calls == ["example.com"] * 2


def test_a_limiter_with_cache_settings_keeps_its_own_cache(fakes) -> None:
    resolver = fakes.Resolver()
    limiter = _limiter(cache_ttl_seconds=600)
    services = SecurityServices(resolver=resolver, dns_rate_limiter=limiter)
    parse_url("https://example.com/", check_dns=True, services=services)
    parse_url("https://example.com/", check_dns=True, services=services)
    assert resolver.calls == ["example.com"]
    assert get_resolution_cache().get("example.com") is None
    assert limiter.stats()["cached_hosts"] == 1.0

    limiter.reset()  # 1.2.0's reset() also emptied the cache
    assert limiter.stats()["cached_hosts"] == 0.0


def test_an_injected_resolution_cache_wins_over_limiter_settings(fakes) -> None:
    from urlps import DNSCacheConfig, DNSResolutionCache

    resolver = fakes.Resolver()
    services = SecurityServices(
        resolver=resolver,
        dns_rate_limiter=_limiter(cache_ttl_seconds=600),
        resolution_cache=DNSResolutionCache(DNSCacheConfig(ttl_seconds=0)),
    )
    parse_url("https://example.com/", check_dns=True, services=services)
    parse_url("https://example.com/", check_dns=True, services=services)
    assert resolver.calls == ["example.com"] * 2


# -- DNSRateLimiter.cached_resolution / store_resolution --------------------


def test_cache_methods_still_work_on_the_cache_the_limiter_uses() -> None:
    addr_info = [(2, 1, 6, "", ("93.184.216.34", 80))]

    plain = DNSRateLimiter()
    with pytest.warns(DeprecationWarning, match="store_resolution"):
        plain.store_resolution("example.com", addr_info)
    # Without its own settings, a limiter's lookups use the process-global cache.
    assert get_resolution_cache().get("example.com") is not None
    with pytest.warns(DeprecationWarning, match="cached_resolution"):
        entry = plain.cached_resolution("example.com")
    assert entry is not None
    assert entry.addr_info == tuple(addr_info)

    own = _limiter(cache_ttl_seconds=600)
    with pytest.warns(DeprecationWarning):
        own.store_resolution("own.example", None)  # a negative answer
    with pytest.warns(DeprecationWarning):
        assert own.cached_resolution("own.example") is not None
    assert get_resolution_cache().get("own.example") is None


def test_resetting_the_global_limiter_forgets_cached_answers() -> None:
    """In 1.2.0 the global cache belonged to the global limiter; tests relied on this reset."""
    get_resolution_cache().store("example.com", [(2, 1, 6, "", ("93.184.216.34", 80))])
    reset_dns_rate_limiter()
    assert get_resolution_cache().get("example.com") is None


# -- SecurityPolicy fields added since 1.1 are keyword-only -----------------


def test_fields_added_after_1_1_cannot_be_passed_positionally() -> None:
    import dataclasses

    released_1_1 = 21  # name ... dns_rate_limiter
    positional = [f for f in dataclasses.fields(SecurityPolicy) if f.kw_only is False]
    assert len(positional) == released_1_1
    with pytest.raises(TypeError):
        SecurityPolicy(*([None] * (released_1_1 + 1)))
    policy = SecurityPolicy("custom", phishing_fail_closed=True, dns_deadline_seconds=1.0)
    assert policy.phishing_fail_closed is True
