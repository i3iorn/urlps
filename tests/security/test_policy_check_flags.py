"""A check enabled on the policy must actually run.

``parse_url``/``join``/``build_secure`` used to default ``check_dns`` and
``check_phishing`` to ``False`` and pass that on as an explicit override, so
``parse_url(url, policy=SecurityPolicy.strict(check_dns=True))`` silently ran
no DNS check at all. ``None`` now means "defer to the policy".
"""

from __future__ import annotations

import pytest

from urlps import URL, SecurityPolicy, build_secure, join, parse_url


@pytest.fixture
def resolver(fakes):
    return fakes.Resolver()


@pytest.fixture
def feed(fakes):
    return fakes.Feed()


@pytest.fixture
def services(fakes, resolver, feed):
    return fakes.services(resolver=resolver, feed=feed)


def test_policy_check_dns_runs_through_parse_url(services, resolver) -> None:
    parse_url("https://api.example.com/", policy=SecurityPolicy.strict(check_dns=True), services=services)
    assert resolver.calls == ["api.example.com"]


def test_policy_check_dns_runs_through_join_and_build_secure(services, resolver) -> None:
    policy = SecurityPolicy.balanced(check_dns=True)
    join("https://example.com/a", "/b", policy=policy, services=services)
    build_secure("https", "api.example.com", policy=policy, services=services)
    assert resolver.calls == ["example.com", "api.example.com"]


def test_policy_check_dns_runs_through_url_constructor_and_mutations(services, resolver) -> None:
    url = URL("https://api.example.com/", security_policy=SecurityPolicy.strict(check_dns=True), services=services)
    url.with_path("/other")
    assert len(resolver.calls) == 2


def test_explicit_argument_still_overrides_the_policy(services, resolver) -> None:
    parse_url(
        "https://api.example.com/", policy=SecurityPolicy.strict(check_dns=True), check_dns=False, services=services
    )
    assert resolver.calls == []
    parse_url("https://api.example.com/", policy="strict", check_dns=True, services=services)
    assert len(resolver.calls) == 1


def test_default_still_runs_no_network_checks(services, resolver, feed) -> None:
    parse_url("https://api.example.com/", services=services)
    assert resolver.calls == []
    assert feed.calls == []


def test_policy_check_phishing_runs_through_parse_url(services, feed) -> None:
    parse_url("https://api.example.com/", policy=SecurityPolicy.strict(check_phishing=True), services=services)
    assert feed.calls == ["api.example.com"]
