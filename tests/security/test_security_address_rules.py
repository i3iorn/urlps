"""Caller-supplied ``allowed_addresses`` / ``denied_addresses`` rules.

Rules are matched against what a host *is* -- every IP spelling, IPv4
embedded in IPv6, IDNA/case/trailing-dot variants of a name -- and against
every DNS-resolved address. Deny always wins, applies even with
``enforce_ssrf=False``, and an invalid rule fails at policy construction
rather than silently matching nothing.
"""

from __future__ import annotations

import ipaddress
import socket
from unittest.mock import patch

import pytest

from urlps import (
    DNSRateLimiter,
    InvalidURLError,
    SecurityPolicy,
    SecurityPolicyError,
    join,
    parse_url,
)
from urlps._security.address_rules import AddressList


def _accepted(url: str, policy: SecurityPolicy) -> bool:
    try:
        parse_url(url, policy=policy)
    except InvalidURLError:
        return False
    return True


# ---------------------------------------------------------------------------
# Compiling rules
# ---------------------------------------------------------------------------


def test_rules_compile_every_supported_form() -> None:
    rules = AddressList.from_rules(
        [
            "10.1.0.0/16",
            "192.0.2.7",
            "[fd12::1]",
            "fd12:3456::/32",
            ipaddress.ip_address("203.0.113.9"),
            ipaddress.ip_network("198.51.100.0/24"),
            "Build.Internal.",
            ".corp.example",
            "bücher.example",
            "0x0a000001",  # inet_aton spelling -> 10.0.0.1
        ]
    )
    assert {str(n) for n in rules.networks} == {
        "10.1.0.0/16",
        "192.0.2.7/32",
        "fd12::1/128",
        "fd12:3456::/32",
        "203.0.113.9/32",
        "198.51.100.0/24",
        "10.0.0.1/32",
    }
    assert rules.hostnames == frozenset({"build.internal", "xn--bcher-kva.example"})
    assert rules.domains == ("corp.example",)


@pytest.mark.parametrize(
    "bad",
    [
        "10.0.0.0/33",
        "10.0.0.1/24",  # host bits set: almost always a typo for 10.0.0.0/24
        "fd12::/129",
        "*.example.com",
        "",
        "   ",
        "bad host!",
        "exa mple.com",
        "-leading-hyphen.example",
        "‮example.com",  # IDNA refuses it
        123,
        None,
    ],
)
def test_invalid_rule_fails_at_policy_construction(bad: object) -> None:
    with pytest.raises(SecurityPolicyError):
        SecurityPolicy.strict(denied_addresses=[bad])  # type: ignore[list-item]


def test_a_single_string_is_not_mistaken_for_a_list_of_characters() -> None:
    with pytest.raises(SecurityPolicyError):
        SecurityPolicy.strict(allowed_addresses="10.0.0.0/8")


def test_policy_with_rules_stays_hashable_and_comparable() -> None:
    first = SecurityPolicy.strict(allowed_addresses=["10.0.0.0/8"], denied_addresses=["10.0.0.5"])
    second = SecurityPolicy.strict(allowed_addresses=["10.0.0.0/8"], denied_addresses=["10.0.0.5"])
    assert first == second
    assert hash(first) == hash(second)
    assert SecurityPolicy.strict() != first


@pytest.mark.parametrize("factory", ["strict", "balanced", "internal", "local"])
def test_every_preset_accepts_rules(factory: str) -> None:
    policy = getattr(SecurityPolicy, factory)(allowed_addresses=["10.9.0.0/16"], denied_addresses=["evil.example"])
    assert policy.host_is_allowed("10.9.1.1")
    assert policy.host_is_denied("EVIL.example.")


# ---------------------------------------------------------------------------
# Allow rules
# ---------------------------------------------------------------------------

ALLOW_CASES = [
    # (rules, accepted, still rejected)
    (["10.1.0.0/16"], ["http://10.1.2.3/", "http://[::ffff:10.1.2.3]/", "http://0x0a010203/"], ["http://10.2.0.1/"]),
    (["100.64.0.1"], ["http://100.64.0.1/", "http://1681915905/"], ["http://100.64.0.2/"]),
    (["100.64.0.0/10"], ["http://100.100.100.200/"], ["http://169.254.169.254/"]),
    (["fd12:3456::/32"], ["http://[fd12:3456::1]/"], ["http://[fd12:3457::1]/"]),
    (["build.internal"], ["http://build.internal/", "http://BUILD.internal./"], ["http://x.build.internal/"]),
    (
        [".corp.internal"],
        ["http://corp.internal/", "http://a.b.corp.internal/"],
        ["http://evilcorp.internal/", "http://corp.internalx.internal/"],
    ),
    (["169.254.169.254"], ["http://169.254.169.254/"], ["http://169.254.170.2/"]),
]


@pytest.mark.parametrize("rules,accepted,rejected", ALLOW_CASES)
def test_allowed_addresses_exempt_exactly_what_they_cover(
    rules: list[str], accepted: list[str], rejected: list[str]
) -> None:
    policy = SecurityPolicy.strict(allowed_addresses=rules)
    for url in accepted:
        assert _accepted(url, policy), url
    for url in rejected:
        assert not _accepted(url, policy), url


def test_allow_rule_cannot_be_smuggled_through_a_differential_spelling() -> None:
    """The parsed host must be allowed on its own merits, not via the raw text."""
    policy = SecurityPolicy.strict(allowed_addresses=["example.com"])
    assert not _accepted("http://127。0。0。1/", policy)
    assert not _accepted("http://127.0.0.1?example.com", policy)


def test_allow_rule_applies_to_with_host_and_join() -> None:
    policy = SecurityPolicy.strict(allowed_addresses=["10.1.0.0/16"])
    base = parse_url("https://example.com/", policy=policy)
    assert base.with_host("10.1.0.5").host == "10.1.0.5"
    with pytest.raises(InvalidURLError):
        base.with_host("10.2.0.5")
    assert join("https://example.com/a", "//10.1.0.6/b", policy=policy).host == "10.1.0.6"


def test_allow_rule_extends_the_local_policy() -> None:
    policy = SecurityPolicy.local(allowed_addresses=["100.64.0.0/10"])
    assert _accepted("http://100.101.102.103/", policy)
    assert not _accepted("http://169.254.169.254/", policy)


# ---------------------------------------------------------------------------
# Deny rules
# ---------------------------------------------------------------------------

DENY_CASES = [
    (
        ["1.1.1.0/24"],
        ["http://1.1.1.1/", "http://16843009/", "http://0x01010101/", "http://[::ffff:1.1.1.1]/"],
        ["http://1.0.0.1/"],
    ),
    (["2606:4700:4700::/48"], ["http://[2606:4700:4700::1111]/"], ["http://[2001:4860:4860::8888]/"]),
    (["tracker.example"], ["http://tracker.example/", "http://TRACKER.example./"], ["http://a.tracker.example/"]),
    ([".ads.example"], ["http://ads.example/", "http://cdn.ads.example/"], ["http://notads.example/"]),
    (["bücher.example"], ["http://bücher.example/", "http://xn--bcher-kva.example/"], ["http://buecher.example/"]),
]


@pytest.mark.parametrize("rules,denied,accepted", DENY_CASES)
def test_denied_addresses_reject_every_spelling(rules: list[str], denied: list[str], accepted: list[str]) -> None:
    policy = SecurityPolicy.strict(denied_addresses=rules)
    for url in denied:
        with pytest.raises(InvalidURLError) as excinfo:
            parse_url(url, policy=policy)
        assert excinfo.value.code is not None
        assert excinfo.value.code.value == "ssrf_risk"
        assert "denied address rule" in excinfo.value.message
    for url in accepted:
        assert _accepted(url, policy), url


def test_deny_wins_over_allow() -> None:
    policy = SecurityPolicy.strict(
        allowed_addresses=["10.0.0.0/8", ".corp.example"], denied_addresses=["10.0.0.5", "hr.corp.example"]
    )
    assert _accepted("http://10.0.0.6/", policy)
    assert not _accepted("http://10.0.0.5/", policy)
    assert _accepted("http://eng.corp.example/", policy)
    assert not _accepted("http://hr.corp.example/", policy)


def test_deny_applies_even_with_ssrf_enforcement_off() -> None:
    policy = SecurityPolicy.internal(enforce_ssrf=False, denied_addresses=["169.254.169.254", "10.0.0.0/8"])
    assert _accepted("http://127.0.0.1/", policy)
    assert not _accepted("http://169.254.169.254/", policy)
    assert not _accepted("http://10.1.2.3/", policy)


def test_deny_applies_to_userinfo_and_mutation_paths() -> None:
    policy = SecurityPolicy.balanced(denied_addresses=["blocked.example"])
    base = parse_url("https://example.com/", policy=policy)
    with pytest.raises(InvalidURLError):
        base.with_host("blocked.example")
    with pytest.raises(InvalidURLError):
        base.with_netloc("user@blocked.example")


# ---------------------------------------------------------------------------
# Rules apply to DNS-resolved addresses too
# ---------------------------------------------------------------------------


def _resolves_to(address: str):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return patch(
        "urlps._security.dns_guard._resolve_addr_info",
        return_value=[(family, socket.SOCK_STREAM, 6, "", (address, 80))],
    )


def _dns_accepted(url: str, **policy_kwargs) -> bool:
    policy = SecurityPolicy.strict(check_dns=True, dns_rate_limiter=DNSRateLimiter(), **policy_kwargs)
    with patch("urlps._security.dns_guard._verify_connection_safe", return_value=True, create=True):
        return _accepted(url, policy)


def test_resolution_into_allowed_network_is_accepted() -> None:
    with _resolves_to("10.1.2.3"):
        assert not _dns_accepted("https://build.example/")
        assert _dns_accepted("https://build.example/", allowed_addresses=["10.1.0.0/16"])


def test_hostname_allow_rule_trusts_resolution_except_metadata() -> None:
    with _resolves_to("10.9.9.9"):
        assert _dns_accepted("https://build.example/", allowed_addresses=["build.example"])
        assert not _dns_accepted(
            "https://build.example/", allowed_addresses=["build.example"], denied_addresses=["10.9.0.0/16"]
        )
    with _resolves_to("169.254.169.254"):
        assert not _dns_accepted("https://build.example/", allowed_addresses=["build.example"])
    with _resolves_to("fd00:ec2::254"):
        assert not _dns_accepted("https://build.example/", allowed_addresses=[".example"])


def test_resolution_into_denied_network_is_rejected() -> None:
    with _resolves_to("1.1.1.1"):
        assert _dns_accepted("https://public.example/")
        assert not _dns_accepted("https://public.example/", denied_addresses=["1.1.1.0/24"])
    with _resolves_to("64:ff9b::101:101"):
        assert not _dns_accepted(
            "https://public.example/", allowed_addresses=["64:ff9b::/96"], denied_addresses=["1.1.1.0/24"]
        )
