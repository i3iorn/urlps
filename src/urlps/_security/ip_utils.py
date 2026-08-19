"""IP and host safety helpers for security checks."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable, Sequence
from functools import lru_cache

from .._cache_config import SECURITY_CACHE_SIZE
from ..constants import BLOCKED_HOSTNAMES, LOOPBACK_HOSTNAMES, METADATA_HOSTNAMES

# `X | Y` works here at runtime (not just in annotations) because it's a
# plain module-level assignment, not something `from __future__ import
# annotations` defers -- and PEP 604's `|` between two classes is a native
# runtime operation from Python 3.10, which matches requires-python.
IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
AddrInfo = Sequence[tuple[int, int, int, str, tuple]]


def _is_ip_safe(ip: IpAddress) -> bool:
    """Check if IP is safe (not private/reserved)."""
    return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_link_local)


def _check_ipv4_private(host: str) -> bool:
    """Check if IPv4 address is private/reserved."""
    try:
        return not _is_ip_safe(ipaddress.IPv4Address(host))
    except (ValueError, ipaddress.AddressValueError):
        return False


def _strip_ipv6_brackets(host: str) -> str:
    """Strip brackets and encoded zone ID from IPv6 address."""
    if host.startswith("[") and host.endswith("]"):
        inner = host[1:-1]
        if "%25" in inner:
            inner, _, _ = inner.partition("%25")
        return inner
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
    """Check if hostname is in blocklist or blocked suffixes."""
    if host_lower in BLOCKED_HOSTNAMES:
        return True
    return host_lower.endswith(".local") or host_lower.endswith(".localhost") or host_lower.endswith(".internal")


def _is_ipv4_mapped_ipv6(host_lower: str) -> bool:
    """Check for IPv4-mapped IPv6 addresses."""
    return host_lower.startswith("[::ffff:")


def _parse_ip_octet(part: str) -> int | None:
    """Parse IP octet in decimal, octal, or hex format."""
    lower_part = part.lower()
    try:
        if lower_part.startswith("0x"):
            return int(lower_part, 16)
        if part.startswith("0") and len(part) > 1 and part.isdigit():
            return int(part, 8)
        if part.isdigit():
            return int(part)
    except ValueError:
        return None
    return None


def _is_decimal_ip_private(host: str) -> bool:
    """Check decimal IPv4 format (e.g., 2130706433 for 127.0.0.1)."""
    if not host.isdigit():
        return False
    try:
        decimal_ip = int(host)
        if 0 <= decimal_ip <= 0xFFFFFFFF:
            ip_str = ".".join(str(octet) for octet in decimal_ip.to_bytes(4, "big"))
            return not _is_ip_safe(ipaddress.IPv4Address(ip_str))
    except (ValueError, OverflowError, ipaddress.AddressValueError):
        return False
    return False


def _is_octal_hex_ip_private(host: str) -> bool:
    """Check octal/hex IPv4 representations (e.g., 0177.0.0.1)."""
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

    if not all(0 <= octet <= 255 for octet in octets):
        return False

    try:
        dotted = ".".join(str(octet) for octet in octets)
        return not _is_ip_safe(ipaddress.IPv4Address(dotted))
    except (ValueError, ipaddress.AddressValueError):
        return False


def _parse_inet_aton_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Parse a host using the classic inet_aton(3) grammar, or return None.

    This is deliberately broader than ``ipaddress.IPv4Address``, because it is
    what C resolvers, libcurl, and most HTTP clients actually accept:

        a          -- a single 32-bit value          (0x7f000001 -> 127.0.0.1)
        a.b        -- b is 24 bits                   (127.1      -> 127.0.0.1)
        a.b.c      -- c is 16 bits                   (127.0.1    -> 127.0.0.1)
        a.b.c.d    -- each 8 bits                    (127.0.0.1)

    Each part may be decimal, octal (leading ``0``), or hex (``0x`` prefix).

    Without this, obfuscated single-value forms bypassed SSRF checks entirely:
    ``http://0x7f000001/`` and ``http://017700000001/`` both address 127.0.0.1
    but were accepted, because the decimal check required an all-digit string
    within 32 bits (so it never tried octal) and the octal/hex check required
    exactly four dot-separated parts.
    """
    if not host or not isinstance(host, str):
        return None

    parts = host.split(".")
    if len(parts) > 4:
        return None

    values: list[int] = []
    for part in parts:
        value = _parse_ip_octet(part)
        if value is None or value < 0:
            return None
        values.append(value)

    # The final part absorbs all remaining bytes; the leading parts are octets.
    leading, last = values[:-1], values[-1]
    if any(octet > 0xFF for octet in leading):
        return None

    remaining_bits = 8 * (4 - len(leading))
    if last >= (1 << remaining_bits):
        return None

    packed = last
    for index, octet in enumerate(reversed(leading)):
        packed |= octet << (remaining_bits + 8 * index)

    try:
        return ipaddress.IPv4Address(packed)
    except (ValueError, ipaddress.AddressValueError):
        return None


def _is_obfuscated_ip_private(host: str) -> bool:
    """Check whether host addresses a private/reserved IP in any inet_aton form."""
    address = _parse_inet_aton_ipv4(host)
    if address is None:
        return False
    return not _is_ip_safe(address)


def _check_direct_ip_safe(host: str) -> bool | None:
    """Check if host is a direct IP and if it is safe; None if not an IP."""
    try:
        return _is_ip_safe(ipaddress.ip_address(host))
    except ValueError:
        return None


def _check_resolved_ips_safe(addr_info: Iterable[tuple[int, int, int, str, tuple]]) -> bool:
    """Check that all resolved IPs in addr_info are safe.

    Fails closed: an address we cannot parse is treated as unsafe rather than
    skipped, and an empty result is unsafe too. Previously an unparseable
    address hit ``continue``, so a resolution yielding only unparseable
    addresses returned "safe" without a single address having been checked.
    """
    checked_any = False
    for _family, _socktype, _proto, _canonname, sockaddr in addr_info:
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except (ValueError, IndexError, TypeError):
            return False
        if not _is_ip_safe(address):
            return False
        checked_any = True
    return checked_any


def _verify_connection_safe(
    addr_info: Iterable[tuple[int, int, int, str, tuple]],
    timeout: float,
    *,
    fail_open_on_error: bool = True,
) -> bool:
    """Verify connection peer IP safety to mitigate DNS rebinding.

    Only transport failures honour ``fail_open_on_error`` -- that is a
    deliberate, policy-driven availability tradeoff. Being unable to
    *determine* the peer is not a transport failure and always fails closed:
    an empty address list or an unparseable peer address means the check did
    not run, which is not the same as the check passing.
    """
    addresses = list(addr_info)
    if not addresses:
        return False

    family, socktype, proto, _canonname, sockaddr = addresses[0]
    test_socket = socket.socket(family, socktype, proto)
    try:
        test_socket.settimeout(timeout)
        test_socket.connect(sockaddr)
        try:
            return _is_ip_safe(ipaddress.ip_address(test_socket.getpeername()[0]))
        except (ValueError, IndexError, TypeError):
            return False
    except (TimeoutError, OSError):
        return bool(fail_open_on_error)
    finally:
        test_socket.close()


@lru_cache(maxsize=SECURITY_CACHE_SIZE)
def is_private_ip(host: str) -> bool:
    """Check if host is a private/reserved IP address."""
    if not isinstance(host, str):
        return False
    return _check_ipv4_private(host) or _check_ipv6_private(host)


def _resolve_host_to_ip(host: str) -> IpAddress | None:
    """Best-effort literal-IP resolution, obfuscated spellings included.

    Returns None for genuine hostnames (which need DNS, out of scope here).
    """
    stripped = _strip_ipv6_brackets(host)
    for factory in (ipaddress.IPv6Address, ipaddress.IPv4Address):
        try:
            return factory(stripped)
        except (ValueError, ipaddress.AddressValueError):
            continue
    # Decimal / octal / hex / short-form inet_aton spellings.
    return _parse_inet_aton_ipv4(host)


def _is_permitted_private_host(host: str, host_lower: str) -> bool:
    """Whether ``local`` policy may permit this host.

    True only for loopback/RFC1918/ULA. Link-local (which is where the cloud
    metadata endpoints live), multicast, reserved and unspecified addresses
    are never permitted, nor is anything in METADATA_HOSTNAMES.
    """
    if host_lower in METADATA_HOSTNAMES or host_lower.endswith(".internal"):
        return False

    ip = _resolve_host_to_ip(host_lower)
    if ip is not None:
        # Order matters. Link-local is checked first because it is where the
        # cloud metadata endpoints live and because IPv6 link-local is also
        # is_private. is_reserved is deliberately NOT a veto: IPv6 ::1 is both
        # loopback and reserved (it falls inside ::/8), and a reserved address
        # that is neither loopback nor private simply fails the permit below
        # and stays risky anyway.
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return False
        return bool(ip.is_loopback or ip.is_private)

    # Hostname, not a literal: only the explicit loopback spellings and the
    # loopback/mDNS suffixes qualify.
    return host_lower in LOOPBACK_HOSTNAMES or host_lower.endswith((".local", ".localhost"))


@lru_cache(maxsize=SECURITY_CACHE_SIZE)
def is_ssrf_risk(host: str, *, allow_private: bool = False) -> bool:
    """Check if host poses SSRF risk (blocked hostnames, private IPs, and ambiguous IPs).

    ``_is_obfuscated_ip_private`` subsumes the two narrower checks above it;
    they are retained because overlapping checks in a security OR-chain are
    defensive, not harmful.

    ``allow_private=True`` (the ``local`` policy) *narrows* this rather than
    disabling it: loopback and RFC1918/ULA hosts stop being risks, but cloud
    metadata endpoints, the link-local range, ``.internal``, kubernetes service
    names, multicast, reserved and 0.0.0.0 all still are.
    """
    if not isinstance(host, str) or not host:
        return False
    host_lower = host.lower().rstrip(".")

    risky = (
        _is_blocked_hostname(host_lower)
        or _is_ipv4_mapped_ipv6(host_lower)
        or _is_decimal_ip_private(host)
        or _is_octal_hex_ip_private(host)
        or _is_obfuscated_ip_private(host)
        or is_private_ip(host)
    )

    if risky and allow_private:
        return not _is_permitted_private_host(host, host_lower)

    return risky


def is_malicious_ipv6_zone_id(host: str) -> bool:
    """Check if IPv6 zone identifier contains malicious content."""
    if not isinstance(host, str):
        return False
    if "%25" not in host and "%" not in host:
        return False
    if not (host.startswith("[") and "]" in host):
        return False

    try:
        inner = host[1 : host.index("]")]
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
