"""IP and host safety checks used by URL security validation."""
from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache
from typing import Optional, Union

from ..constants import BLOCKED_HOSTNAMES


def _is_ip_safe(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Check if IP is safe (not private/reserved)."""
    return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_link_local)


def _check_ipv4_private(host: str) -> bool:
    """Check if IPv4 address is private/reserved."""
    try:
        return not _is_ip_safe(ipaddress.IPv4Address(host))
    except (ValueError, ipaddress.AddressValueError):
        return False


def _strip_ipv6_brackets(host: str) -> str:
    """Strip brackets and zone ID from IPv6 address."""
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
        if "%25" in host:
            host, _, _ = host.partition("%25")
    return host


def _check_ipv6_private(host: str) -> bool:
    """Check if IPv6 address (bracketed) is private/reserved."""
    if not host.startswith("[") or not host.endswith("]"):
        return False
    try:
        inner = _strip_ipv6_brackets(host)
        return not _is_ip_safe(ipaddress.IPv6Address(inner))
    except (ValueError, ipaddress.AddressValueError):
        return False


def _is_blocked_hostname(host_lower: str) -> bool:
    """Check if hostname is in the blocklist."""
    if host_lower in BLOCKED_HOSTNAMES:
        return True
    return host_lower.endswith(".local") or host_lower.endswith(".localhost") or host_lower.endswith(".internal")


def _is_ipv4_mapped_ipv6(host_lower: str) -> bool:
    """Check for IPv4-mapped IPv6 addresses."""
    return host_lower.startswith("[::ffff:")


def _parse_ip_octet(part: str) -> Optional[int]:
    """Parse IP octet in decimal, octal, or hex format."""
    part_lower = part.lower()
    try:
        if part_lower.startswith("0x"):
            return int(part_lower, 16)
        if part.startswith("0") and len(part) > 1 and part.isdigit():
            return int(part, 8)
        if part.isdigit():
            return int(part)
    except ValueError:
        return None
    return None


def _is_decimal_ip_private(host: str) -> bool:
    """Check decimal IP format (e.g., 2130706433 = 127.0.0.1)."""
    if not host.isdigit():
        return False
    try:
        decimal_ip = int(host)
        if 0 <= decimal_ip <= 0xFFFFFFFF:
            ip_str = ".".join(str(b) for b in decimal_ip.to_bytes(4, "big"))
            return not _is_ip_safe(ipaddress.IPv4Address(ip_str))
    except (ValueError, OverflowError, ipaddress.AddressValueError):
        return False
    return False


def _is_octal_hex_ip_private(host: str) -> bool:
    """Check octal/hex IP format (e.g., 0177.0.0.1)."""
    if "." not in host:
        return False
    parts = host.split(".")
    if len(parts) != 4:
        return False

    octets = []
    for part in parts:
        octet = _parse_ip_octet(part)
        if octet is None:
            return False
        octets.append(octet)

    if not all(0 <= o <= 255 for o in octets):
        return False
    try:
        return not _is_ip_safe(ipaddress.IPv4Address(".".join(str(o) for o in octets)))
    except (ValueError, ipaddress.AddressValueError):
        return False


def _check_direct_ip_safe(host: str) -> Optional[bool]:
    """Check if host is a direct IP and if it's safe. Returns None if not IP."""
    try:
        return _is_ip_safe(ipaddress.ip_address(host))
    except ValueError:
        return None


def _check_resolved_ips_safe(addr_info: object) -> bool:
    """Check if all resolved IPs are safe."""
    for _family, _socktype, _proto, _canonname, sockaddr in addr_info:  # type: ignore[misc]
        try:
            if not _is_ip_safe(ipaddress.ip_address(sockaddr[0])):
                return False
        except ValueError:
            continue
    return True


def _verify_connection_safe(addr_info: object, timeout: float) -> bool:
    """Verify connection is safe against DNS rebinding."""
    if not addr_info:
        return True

    family, socktype, proto, _canonname, sockaddr = addr_info[0]  # type: ignore[index]
    test_sock = socket.socket(family, socktype, proto)
    try:
        test_sock.settimeout(timeout)
        test_sock.connect(sockaddr)
        try:
            return _is_ip_safe(ipaddress.ip_address(test_sock.getpeername()[0]))
        except ValueError:
            return True
    except (socket.timeout, OSError):
        return True
    finally:
        test_sock.close()


@lru_cache(maxsize=512)
def is_private_ip(host: str) -> bool:
    """Check if host is a private/reserved IP address."""
    if not isinstance(host, str):
        return False
    return _check_ipv4_private(host) or _check_ipv6_private(host)


@lru_cache(maxsize=512)
def is_ssrf_risk(host: str) -> bool:
    """Check if host poses SSRF risk (blocked hostnames, private IPs, etc.)."""
    if not isinstance(host, str) or not host:
        return False
    host_lower = host.lower().rstrip(".")
    return (
        _is_blocked_hostname(host_lower)
        or _is_ipv4_mapped_ipv6(host_lower)
        or _is_decimal_ip_private(host)
        or _is_octal_hex_ip_private(host)
        or is_private_ip(host)
    )


def is_malicious_ipv6_zone_id(host: str) -> bool:
    """Check if IPv6 zone identifier contains malicious content."""
    if not isinstance(host, str):
        return False

    if "%25" not in host and "%" not in host:
        return False

    if not (host.startswith("[") and "]" in host):
        return False

    try:
        inner = host[1:host.index("]")]
        if "%25" in inner or "%" in inner:
            zone_id = inner.split("%25" if "%25" in inner else "%", 1)[1]
            if not zone_id:
                return True
            for char in zone_id:
                if not (char.isalnum() or char in "-_.~"):
                    return True
    except (ValueError, IndexError):
        return True

    return False

