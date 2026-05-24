from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from typing import Iterable, List, Optional, Union

from ..constants import BLOCKED_HOSTNAMES

logger = logging.getLogger(__name__)

IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def _is_public_ip(ip: IpAddress) -> bool:
    """Return True if the IP address is considered public/safe.

    Args:
        ip: Parsed IPv4 or IPv6 address.

    Returns:
        True if the IP is not private, loopback, multicast, reserved, or link-local.
    """
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_link_local
    )


def _normalize_host(host: str) -> str:
    """Normalize host for comparison and blocklist checks.

    - Strips trailing dot.
    - Lowercases.
    - Leaves IP literals unchanged.
    - Does not perform DNS resolution.

    Args:
        host: Raw host string.

    Returns:
        Normalized host string.
    """
    normalized = host.strip()
    if not normalized:
        return normalized

    normalized = normalized.rstrip(".")
    return normalized.lower()


def _is_canonical_ipv4(host: str) -> bool:
    """Check if host is a canonical dotted-decimal IPv4 address.

    Args:
        host: Host string.

    Returns:
        True if host is canonical IPv4 (no leading zeros, no hex/octal).
    """
    try:
        addr = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        return False

    return host == str(addr)


def _parse_ipv6_literal(host: str) -> Optional[ipaddress.IPv6Address]:
    """Parse a canonical IPv6 literal, optionally bracketed, without zone ID.

    Args:
        host: Host string, possibly in [addr] form.

    Returns:
        Parsed IPv6Address or None if not a canonical literal.
    """
    candidate = host
    if host.startswith("[") and host.endswith("]"):
        candidate = host[1:-1]

    # Strip zone ID if present; zone ID is validated separately.
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]

    try:
        addr = ipaddress.IPv6Address(candidate)
    except ipaddress.AddressValueError:
        return None

    # Require canonical compressed form when bracketed or bare.
    if host.startswith("[") and host.endswith("]"):
        expected = f"[{addr.compressed}]"
        if "%" in host:
            # Zone ID is handled elsewhere; only compare address part.
            address_part = host[1 : host.index("]")]
            address_only = address_part.split("%", 1)[0]
            if address_only.lower() != addr.compressed.lower():
                return None
        else:
            if host.lower() != expected.lower():
                return None
    else:
        if host.lower() != addr.compressed.lower():
            return None

    return addr


def _looks_like_ambiguous_ip_representation(host: str) -> bool:
    """Detect decimal, octal, hex, or mixed IP representations.

    Any such representation is treated as unsafe to avoid ambiguity.

    Args:
        host: Host string.

    Returns:
        True if host looks like a non-canonical IP representation.
    """
    if not host:
        return False

    # Pure decimal integer (e.g., 2130706433 for 127.0.0.1).
    if host.isdigit():
        return True

    if "." not in host:
        return False

    parts = host.split(".")
    if not 2 <= len(parts) <= 4:
        return False

    for part in parts:
        if not part:
            return True
        # Hex (0x7f)
        if part.lower().startswith("0x"):
            return True
        # Leading zero decimal (0177) or octal-like.
        if len(part) > 1 and part[0] == "0" and part.isdigit():
            return True
        # Non-digit characters (other than allowed in canonical IPv4).
        if not part.isdigit():
            return True

    # If we reach here, it is dotted-decimal but may have leading zeros.
    # Canonical check will handle exact match; anything else is ambiguous.
    if not _is_canonical_ipv4(host):
        return True

    return False


def _is_blocked_hostname(host: str) -> bool:
    """Check if hostname is in the blocklist or uses blocked suffixes.

    Args:
        host: Normalized host (lowercased, no trailing dot).

    Returns:
        True if host is blocked.
    """
    if not host:
        return True

    if host in BLOCKED_HOSTNAMES:
        return True

    blocked_suffixes = (
        ".local",
        ".localhost",
        ".internal",
        ".home.arpa",
        ".lan",
        ".corp",
        ".domain",
    )

    if host == "localhost":
        return True

    return any(host.endswith(suffix) for suffix in blocked_suffixes)


def _iter_ips_from_literal(host: str) -> List[IpAddress]:
    """Parse IP literals (IPv4 or IPv6) into a list of addresses.

    Args:
        host: Host string.

    Returns:
        List of parsed IP addresses. Empty if not a literal or invalid.
    """
    if _looks_like_ambiguous_ip_representation(host):
        # Ambiguous representations are treated as unsafe elsewhere.
        return []

    if _is_canonical_ipv4(host):
        try:
            return [ipaddress.IPv4Address(host)]
        except ipaddress.AddressValueError:
            return []

    ipv6 = _parse_ipv6_literal(host)
    if ipv6 is not None:
        return [ipv6]

    return []


def _all_ips_public(ips: Iterable[IpAddress]) -> bool:
    """Check that all IPs in the iterable are public.

    Args:
        ips: Iterable of IP addresses.

    Returns:
        True if all IPs are public.
    """
    for ip in ips:
        if not _is_public_ip(ip):
            return False
    return True


def _has_ipv4_mapped_ipv6(ip: IpAddress) -> bool:
    """Check if IPv6 address is an IPv4-mapped IPv6 address.

    Args:
        ip: Parsed IP address.

    Returns:
        True if IPv6 address is IPv4-mapped.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return True
    return False


def _is_safe_literal_ip(host: str) -> bool:
    """Check if a literal IP host is public and not IPv4-mapped IPv6.

    Args:
        host: Host string.

    Returns:
        True if host is a literal IP and considered safe.
    """
    ips = _iter_ips_from_literal(host)
    if not ips:
        return False

    for ip in ips:
        if _has_ipv4_mapped_ipv6(ip):
            return False
        if not _is_public_ip(ip):
            return False

    return True


def _is_safe_zone_id(zone_id: str) -> bool:
    """Validate IPv6 zone identifier.

    Only allows a strict subset of characters to avoid injection.

    Args:
        zone_id: Zone identifier string.

    Returns:
        True if zone ID is considered safe.
    """
    if not zone_id:
        return False

    if len(zone_id) > 64:
        return False

    for char in zone_id:
        if not (char.isalnum() or char in "-_.~"):
            return False

    return True


@lru_cache(maxsize=512)
def is_private_ip(host: str) -> bool:
    """Check if host is a private/reserved IP address.

    Security-maximalist behavior:
    - Non-string or empty input is treated as private/unsafe (returns True).
    - Ambiguous IP representations are treated as private/unsafe (returns True).
    - Only canonical IP literals are parsed; everything else is considered non-public.

    Args:
        host: Host string.

    Returns:
        True if host is considered private/reserved/unsafe as an IP literal.
    """
    if not isinstance(host, str):
        logger.warning("Non-string host passed to is_private_ip; treating as private.")
        return True

    normalized = host.strip()
    if not normalized:
        logger.warning("Empty host passed to is_private_ip; treating as private.")
        return True

    if _looks_like_ambiguous_ip_representation(normalized):
        logger.warning("Ambiguous IP representation detected; treating as private.")
        return True

    ips = _iter_ips_from_literal(normalized)
    if not ips:
        # Not a literal IP; this function only evaluates literals.
        return False

    return not _all_ips_public(ips)


@lru_cache(maxsize=512)
def is_ssrf_risk(host: str) -> bool:
    """Check if host poses SSRF risk.

    Security-maximalist behavior:
    - Non-string or empty input is treated as SSRF risk.
    - Ambiguous IP representations are treated as SSRF risk.
    - Blocked hostnames and suffixes are treated as SSRF risk.
    - Private/reserved IP literals are treated as SSRF risk.
    - IPv4-mapped IPv6 literals are treated as SSRF risk.
    - Malicious or invalid IPv6 zone IDs are treated as SSRF risk.

    Args:
        host: Host string.

    Returns:
        True if host is considered an SSRF risk.
    """
    if not isinstance(host, str):
        logger.warning("Non-string host passed to is_ssrf_risk; treating as SSRF risk.")
        return True

    raw = host.strip()
    if not raw:
        logger.warning("Empty host passed to is_ssrf_risk; treating as SSRF risk.")
        return True

    normalized = _normalize_host(raw)

    if _is_blocked_hostname(normalized):
        return True

    if _looks_like_ambiguous_ip_representation(raw):
        return True

    if is_malicious_ipv6_zone_id(raw):
        return True

    if is_private_ip(raw):
        return True

    # Literal IP that is public and not mapped IPv6 is allowed.
    if _is_safe_literal_ip(raw):
        return False

    # Non-literal hostnames that are not blocklisted are allowed here.
    return False


def is_malicious_ipv6_zone_id(host: str) -> bool:
    """Check if IPv6 zone identifier contains malicious or unsafe content.

    Security-maximalist behavior:
    - Non-string input is treated as malicious.
    - Missing zone ID when '%' is present is treated as malicious.
    - Zone IDs with characters outside [A-Za-z0-9-_.~] are treated as malicious.
    - Overly long zone IDs are treated as malicious.

    Args:
        host: Host string, possibly containing an IPv6 literal with zone ID.

    Returns:
        True if zone ID is considered malicious or unsafe.
    """
    if not isinstance(host, str):
        logger.warning("Non-string host passed to is_malicious_ipv6_zone_id; treating as malicious.")
        return True

    if "%" not in host and "%25" not in host:
        return False

    if not (host.startswith("[") and "]" in host):
        return True

    try:
        inner = host[1 : host.index("]")]
    except ValueError:
        logger.warning("Malformed IPv6 literal in is_malicious_ipv6_zone_id; treating as malicious.")
        return True

    # Prefer encoded %25 if present; otherwise raw '%'.
    if "%25" in inner:
        parts = inner.split("%25", 1)
    elif "%" in inner:
        parts = inner.split("%", 1)
    else:
        # '%' outside brackets; treat as malicious.
        return True

    if len(parts) != 2:
        return True

    zone_id = parts[1]
    if not _is_safe_zone_id(zone_id):
        return True

    return False
