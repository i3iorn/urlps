"""A check enabled on the policy must actually run.

``parse_url``/``join``/``build_secure`` used to default ``check_dns`` and
``check_phishing`` to ``False`` and pass that on as an explicit override, so
``parse_url(url, policy=SecurityPolicy.strict(check_dns=True))`` silently ran
no DNS check at all. ``None`` now means "defer to the policy".
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from urlps import URL, SecurityPolicy, build_secure, join, parse_url

DNS_CHECK = "urlps._security.check_dns_rebinding_detailed"
PHISHING_CHECK = "urlps._security.check_against_phishing_db_detailed"


@pytest.fixture
def dns_check():
    with patch(DNS_CHECK, return_value=(True, None)) as mocked:
        yield mocked


@pytest.fixture
def phishing_check():
    with patch(PHISHING_CHECK, return_value=(False, True)) as mocked:
        yield mocked


def test_policy_check_dns_runs_through_parse_url(dns_check) -> None:
    parse_url("https://api.example.com/", policy=SecurityPolicy.strict(check_dns=True))
    dns_check.assert_called_once()


def test_policy_check_dns_runs_through_join_and_build_secure(dns_check) -> None:
    policy = SecurityPolicy.balanced(check_dns=True)
    join("https://example.com/a", "/b", policy=policy)
    build_secure("https", "api.example.com", policy=policy)
    assert dns_check.call_count == 2


def test_policy_check_dns_runs_through_url_constructor_and_mutations(dns_check) -> None:
    url = URL("https://api.example.com/", security_policy=SecurityPolicy.strict(check_dns=True))
    url.with_path("/other")
    assert dns_check.call_count == 2


def test_explicit_argument_still_overrides_the_policy(dns_check) -> None:
    parse_url("https://api.example.com/", policy=SecurityPolicy.strict(check_dns=True), check_dns=False)
    dns_check.assert_not_called()
    parse_url("https://api.example.com/", policy="strict", check_dns=True)
    dns_check.assert_called_once()


def test_default_still_runs_no_network_checks(dns_check, phishing_check) -> None:
    parse_url("https://api.example.com/")
    dns_check.assert_not_called()
    phishing_check.assert_not_called()


def test_policy_check_phishing_runs_through_parse_url(phishing_check) -> None:
    parse_url("https://api.example.com/", policy=SecurityPolicy.strict(check_phishing=True))
    phishing_check.assert_called_once_with("api.example.com")
