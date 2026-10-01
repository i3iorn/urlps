"""Which addresses count as internal, in every spelling, on every Python version.

The verdict used to be "not is_private / is_loopback / is_multicast /
is_reserved / is_link_local". 100.64.0.0/10 (shared address space, which
includes Alibaba Cloud's metadata endpoint 100.100.100.200) is none of those,
so it was treated as public; so was IPv6 site-local fec0::/10. The classifier
now also requires ``is_global``, checks an explicit list of non-public ranges
that does not move with the CPython version, and looks through IPv4 addresses
embedded in IPv6 ones.

Every expectation here is meant to hold on every supported interpreter.
"""

from __future__ import annotations

import ipaddress

import pytest

from urlps import InvalidURLError, parse_url, parse_url_local
from urlps._security.ip_utils import (
    _check_resolved_ips_safe,
    _is_ip_safe,
    embedded_ipv4,
    is_metadata_address,
    is_ssrf_risk,
)

UNSAFE_IPV4 = [
    "0.0.0.0",
    "0.1.2.3",
    "10.0.0.1",
    "10.255.255.255",
    "100.64.0.1",
    "100.100.100.200",  # Alibaba Cloud metadata
    "100.127.255.254",
    "127.0.0.1",
    "127.255.255.254",
    "169.254.0.1",
    "169.254.169.254",  # AWS/GCP/Azure/OCI metadata
    "169.254.170.2",  # AWS ECS task credentials
    "169.254.170.23",  # AWS EKS Pod Identity
    "172.16.0.1",
    "172.31.255.254",
    "192.0.0.1",
    "192.0.0.192",
    "192.0.2.1",
    "192.168.0.1",
    "192.168.255.254",
    "198.18.0.1",
    "198.19.255.254",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "239.255.255.250",
    "240.0.0.1",
    "255.255.255.255",
]

# Neighbours of every boundary above, so an off-by-one prefix shows up.
SAFE_IPV4 = [
    "1.1.1.1",
    "8.8.8.8",
    "9.255.255.255",
    "11.0.0.1",
    "100.63.255.255",
    "100.128.0.1",
    "126.255.255.254",
    "128.0.0.1",
    "169.253.255.255",
    "169.255.0.1",
    "172.15.255.255",
    "172.32.0.1",
    "192.167.255.255",
    "192.169.0.1",
    "198.17.255.255",
    "198.20.0.1",
    "223.255.255.254",
]

UNSAFE_IPV6 = [
    "::",
    "::1",
    "::ffff:127.0.0.1",  # IPv4-mapped
    "::ffff:10.0.0.1",
    "::ffff:169.254.169.254",
    "::ffff:100.100.100.200",
    "::ffff:8.8.8.8",  # mapped is never a legitimate outbound target, even to a public IPv4
    "::127.0.0.1",  # IPv4-compatible (deprecated)
    "64:ff9b::7f00:1",  # NAT64 -> 127.0.0.1
    "64:ff9b::a9fe:a9fe",  # NAT64 -> 169.254.169.254
    "64:ff9b::a00:1",  # NAT64 -> 10.0.0.1
    "64:ff9b::808:808",  # NAT64 well-known prefix: blocked as a whole, allowlist it if you run NAT64
    "64:ff9b:1::1",  # NAT64 local-use
    "100::1",  # discard-only
    "2001::1",  # Teredo
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo with a real client address
    "2001:db8::1",  # documentation
    "2002:7f00:1::",  # 6to4 -> 127.0.0.1
    "2002:a9fe:a9fe::",  # 6to4 -> 169.254.169.254
    "2002:808:808::1",  # 6to4 is deprecated as a whole
    "3fff::1",  # documentation
    "5f00::1",  # SRv6 SIDs
    "fc00::1",
    "fd00::1",
    "fd00:ec2::254",  # AWS metadata over IPv6
    "fd00:ec2::23",  # AWS EKS Pod Identity over IPv6
    "fe80::1",
    "febf::1",
    "fec0::1",  # site-local: was treated as public
    "feff::1",
    "ff02::1",
    "ff05::1",
    "ff0e::1",
]

SAFE_IPV6 = [
    "2001:4860:4860::8888",
    "2606:4700:4700::1111",
    "2a00:1450:4001:80b::200e",
    "2620:fe::fe",
    "2001:500:88:200::8",  # just past 2001::/23
]


def _host(address: str) -> str:
    return f"[{address}]" if ":" in address else address


def _rejection_code(url: str, **kwargs) -> str | None:
    try:
        parse_url(url, **kwargs)
    except InvalidURLError as exc:
        return exc.code.value if exc.code is not None else "no-code"
    return None


# ---------------------------------------------------------------------------
# The classifier
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("address", UNSAFE_IPV4 + UNSAFE_IPV6)
def test_non_public_address_is_unsafe(address: str) -> None:
    assert _is_ip_safe(ipaddress.ip_address(address)) is False


@pytest.mark.parametrize("address", SAFE_IPV4 + SAFE_IPV6)
def test_public_unicast_address_is_safe(address: str) -> None:
    assert _is_ip_safe(ipaddress.ip_address(address)) is True


@pytest.mark.parametrize(
    "address,expected",
    [
        ("::ffff:10.0.0.1", ["10.0.0.1"]),
        ("2002:a9fe:a9fe::", ["169.254.169.254"]),
        ("64:ff9b::808:808", ["8.8.8.8"]),
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", ["65.54.227.120", "192.0.2.45"]),
        ("2001:4860:4860::8888", []),
        ("10.0.0.1", []),
    ],
)
def test_embedded_ipv4_sees_through_transition_mechanisms(address: str, expected: list[str]) -> None:
    assert [str(ip) for ip in embedded_ipv4(ipaddress.ip_address(address))] == expected


@pytest.mark.parametrize(
    "address,expected",
    [
        ("169.254.169.254", True),
        ("100.100.100.200", True),
        ("fd00:ec2::254", True),
        ("::ffff:100.100.100.200", True),
        ("64:ff9b::a9fe:a9fe", True),
        ("169.254.169.253", False),
        ("10.0.0.1", False),
        ("fd00::1", False),
    ],
)
def test_metadata_addresses_are_recognized_in_every_form(address: str, expected: bool) -> None:
    assert is_metadata_address(ipaddress.ip_address(address)) is expected


def test_resolved_addresses_use_the_same_classifier() -> None:
    addr_info = [(2, 1, 6, "", ("100.100.100.200", 80))]
    assert _check_resolved_ips_safe(addr_info) is False


# ---------------------------------------------------------------------------
# End to end through parse_url()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("address", UNSAFE_IPV4 + UNSAFE_IPV6)
def test_parse_url_rejects_non_public_literal(address: str) -> None:
    assert _rejection_code(f"http://{_host(address)}/") == "ssrf_risk"


@pytest.mark.parametrize("address", SAFE_IPV4 + SAFE_IPV6)
def test_parse_url_accepts_public_literal(address: str) -> None:
    url = parse_url(f"http://{_host(address)}/")
    assert url.host is not None


def _spellings(address: str) -> list[str]:
    """Decimal, hex, octal and short inet_aton forms of an IPv4 address."""
    value = int(ipaddress.IPv4Address(address))
    a, b, c, d = (int(part) for part in address.split("."))
    return [
        str(value),
        hex(value),
        f"0{value:o}",
        ".".join(f"0{int(part):o}" for part in address.split(".")),
        f"{a}.{(b << 16) | (c << 8) | d}",
        f"{a}.{b}.{(c << 8) | d}",
    ]


@pytest.mark.parametrize("spelling", _spellings("100.64.0.1") + _spellings("100.100.100.200"))
def test_obfuscated_spellings_of_shared_address_space_are_rejected(spelling: str) -> None:
    assert _rejection_code(f"http://{spelling}/") is not None


@pytest.mark.parametrize("spelling", [*_spellings("100.100.100.200"), "[::ffff:100.100.100.200]"])
def test_alibaba_metadata_is_blocked_under_local(spelling: str) -> None:
    with pytest.raises(InvalidURLError):
        parse_url_local(f"http://{spelling}/")


# ---------------------------------------------------------------------------
# The local policy: loopback/private permitted, metadata never
# ---------------------------------------------------------------------------

LOCAL_PERMITTED = [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "[::1]",
    "[fd00::1]",
    "[::ffff:127.0.0.1]",
    "[::ffff:192.168.1.1]",
    "localhost",
    "printer.local",
]

LOCAL_BLOCKED = [
    "169.254.169.254",
    "169.254.170.2",
    "100.100.100.200",
    "100.64.0.1",
    "[fd00:ec2::254]",
    "[fd00:ec2::23]",
    "[::ffff:169.254.169.254]",
    "[::ffff:100.100.100.200]",
    "[64:ff9b::a9fe:a9fe]",
    "[fe80::1]",
    "0.0.0.0",
    "[::]",
    "224.0.0.1",
    "[ff02::1]",
    "0xa9fea9fe",
    "metadata.google.internal",
    "kubernetes.default.svc",
]


@pytest.mark.parametrize("host", LOCAL_PERMITTED)
def test_local_policy_permits_development_hosts(host: str) -> None:
    assert parse_url_local(f"http://{host}/").host is not None


@pytest.mark.parametrize("host", LOCAL_BLOCKED)
def test_local_policy_never_permits_metadata_link_local_or_cgnat(host: str) -> None:
    with pytest.raises(InvalidURLError):
        parse_url_local(f"http://{host}/")


@pytest.mark.parametrize("host", LOCAL_BLOCKED)
def test_is_ssrf_risk_with_allow_private_agrees(host: str) -> None:
    assert is_ssrf_risk(host, allow_private=True) is True
