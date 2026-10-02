"""Parse time and connect time give the same verdict for the same policy (B4).

The parse-time DNS check used to ignore enforce_ssrf and allow_private_hosts
while the connect-time guard honoured them, so SecurityPolicy.local() and
internal(enforce_ssrf=False) rejected a host resolving to 10.0.0.7 in
parse_url(check_dns=True) but connected to it in create_guarded_connection.
Both now ask SecurityPolicy.permits_address.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from urlps import InvalidURLError, SecurityPolicy, parse_url, resolve_and_validate

POLICIES = {
    "strict": SecurityPolicy.strict(),
    "local": SecurityPolicy.local(),
    "internal-no-ssrf": SecurityPolicy.internal(enforce_ssrf=False),
    "allow-10/8": SecurityPolicy.strict(allowed_addresses=["10.0.0.0/8"]),
    "allow-host": SecurityPolicy.strict(allowed_addresses=["build.example"]),
    "deny-public": SecurityPolicy.local(denied_addresses=["93.184.216.0/24"]),
}
ADDRESSES = ["10.0.0.7", "127.0.0.1", "169.254.169.254", "93.184.216.34", "fd00:ec2::254"]


def _parse_accepts(policy: SecurityPolicy, services) -> bool:
    try:
        parse_url("https://build.example/", policy=replace(policy, check_dns=True), services=services)
    except InvalidURLError:
        return False
    return True


def _connect_accepts(policy: SecurityPolicy, services) -> bool:
    try:
        resolve_and_validate("https://build.example/", policy=policy, services=services)
    except InvalidURLError:
        return False
    return True


@pytest.mark.parametrize("address", ADDRESSES)
@pytest.mark.parametrize("policy_name", POLICIES)
def test_parse_time_and_connect_time_agree(policy_name: str, address: str, fakes) -> None:
    policy = POLICIES[policy_name]
    services = fakes.services(resolver=fakes.Resolver(address))
    assert _parse_accepts(policy, services) == _connect_accepts(policy, services)


@pytest.mark.parametrize(
    ("policy_name", "address", "accepted"),
    [
        ("strict", "10.0.0.7", False),
        ("strict", "93.184.216.34", True),
        ("local", "10.0.0.7", True),
        ("local", "127.0.0.1", True),
        ("local", "169.254.169.254", False),
        ("local", "fd00:ec2::254", False),
        ("internal-no-ssrf", "10.0.0.7", True),
        ("allow-10/8", "10.0.0.7", True),
        ("allow-host", "10.0.0.7", True),
        ("allow-host", "169.254.169.254", False),
        ("deny-public", "93.184.216.34", False),
    ],
)
def test_the_shared_rule(policy_name: str, address: str, accepted: bool, fakes) -> None:
    services = fakes.services(resolver=fakes.Resolver(address))
    assert _parse_accepts(POLICIES[policy_name], services) is accepted
