"""Connect-time SSRF protection: resolve once, validate, connect only to what was validated.

Parse-time checks -- including ``parse_url(..., check_dns=True)`` -- cannot
stop DNS rebinding. The HTTP client resolves the host again when it connects,
and an attacker's DNS server can answer with a public address the first time
and ``127.0.0.1`` the second. The only robust defence is to validate the
address that is actually connected to. This module provides two ways to do
that:

* :func:`resolve_and_validate` returns the vetted addresses for a URL, for
  callers that pin the connection to them themselves.
* :func:`create_guarded_connection` is a drop-in replacement for
  :func:`socket.create_connection` (and for urllib3's, which ``requests``
  uses) that resolves, validates every address, connects only to a vetted
  one, and checks the peer address before returning the socket.

Neither can see through an HTTP proxy: with a proxy configured, the guard
validates the connection to the proxy, not the proxy's onward connection.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from typing import Any

from ._host import ip_literal_text
from ._security import _canonical_host, dns_guard
from ._security.ip_utils import AddrInfo, IpAddress
from ._security.policy import PolicyInput, SecurityPolicy, resolve_security_policy
from .constants import DEFAULT_DNS_TIMEOUT
from .exceptions import DNSResolutionError, ErrorCode, InvalidURLError
from .url import URL

__all__ = ["create_guarded_connection", "resolve_and_validate"]


def _sockaddr_ip(sockaddr: tuple) -> IpAddress:
    # IPv6 sockaddrs may carry a scope ("fe80::1%eth0"); the scope is not
    # part of the address.
    return ipaddress.ip_address(str(sockaddr[0]).partition("%")[0])


def _address_permitted(policy: SecurityPolicy, ip: IpAddress, *, host_allowed_by_name: bool) -> bool:
    if not policy.enforce_ssrf:
        # Built-in enforcement is off; only the caller's own deny rules apply.
        return not policy.host_is_denied(str(ip))
    return policy.ip_is_permitted(
        ip, host_allowed_by_name=host_allowed_by_name, allow_private=policy.allow_private_hosts
    )


def _ssrf_error(message: str, host: str) -> InvalidURLError:
    return InvalidURLError(message, component="host", value=host, code=ErrorCode.SSRF_RISK)


def _vetted_addrinfo(host: str, port: int, policy: SecurityPolicy, dns_timeout: float | None) -> AddrInfo:
    """Resolve ``host`` once and return its address info, every entry validated.

    Fails closed: if *any* resolved address is disallowed the whole lookup is
    rejected, rather than quietly connecting to the "good" one -- a name that
    resolves to both a public and an internal address is itself the signature
    of a rebinding attempt.
    """
    if policy.host_is_denied(host) or (policy.enforce_ssrf and policy.host_is_ssrf_risk(host)):
        raise _ssrf_error("Host poses SSRF risk and is disallowed.", host)
    host_allowed_by_name = policy.host_is_allowed(host)

    try:
        # Through the module so the resolver can be substituted in tests.
        addr_info = dns_guard._resolve_addr_info(ip_literal_text(host), dns_timeout, port=port)
    except socket.gaierror as exc:
        raise DNSResolutionError(
            f"Could not resolve host: {exc}", component="host", value=host, code=ErrorCode.DNS_RESOLUTION_FAILED
        ) from exc
    except TimeoutError as exc:
        raise DNSResolutionError(
            "DNS resolution timed out.", component="host", value=host, code=ErrorCode.DNS_RESOLUTION_FAILED
        ) from exc
    if not addr_info:
        raise DNSResolutionError(
            "Host resolved to no addresses.", component="host", value=host, code=ErrorCode.DNS_RESOLUTION_FAILED
        )

    for entry in addr_info:
        try:
            ip = _sockaddr_ip(entry[4])
        except (ValueError, IndexError, TypeError):
            raise _ssrf_error("Host resolved to an address that could not be verified.", host) from None
        if not _address_permitted(policy, ip, host_allowed_by_name=host_allowed_by_name):
            raise _ssrf_error(f"Host resolves to a disallowed address ({ip}).", host)
    return addr_info


def resolve_and_validate(
    url: str | URL,
    *,
    policy: PolicyInput = None,
    port: int | None = None,
    dns_timeout: float | None = DEFAULT_DNS_TIMEOUT,
) -> list[IpAddress]:
    """Resolve a URL's host and return its addresses, all validated under ``policy``.

    Connect to one of the returned addresses (sending the original host in
    the ``Host`` header / SNI) to make the check and the connection see the
    same answer. Re-resolving the name afterwards throws that guarantee away.

    Args:
        url: A URL string (parsed with :func:`urlps.parse_url` under
            ``policy``) or an already-parsed :class:`~urlps.URL`.
        policy: Policy to validate the addresses under. Defaults to the
            URL's own policy for a ``URL``, and to ``strict`` for a string.
        port: Port for the returned address info; defaults to the URL's
            effective port.
        dns_timeout: Bound on the resolution itself, in seconds.

    Raises:
        InvalidURLError: The URL is invalid, or any address is disallowed
            (code ``ssrf_risk``).
        DNSResolutionError: The host could not be resolved.
    """
    if isinstance(url, URL):
        parsed = url
        effective_policy = resolve_security_policy(policy) if policy is not None else url.security_policy
    else:
        from ._entrypoints import parse_url

        parsed = parse_url(url, policy=policy)
        effective_policy = parsed.security_policy
    if not parsed.host:
        raise InvalidURLError("URL has no host to resolve.", component="host")

    target_port = port if port is not None else (parsed.effective_port or 0)
    addresses: dict[IpAddress, None] = {}
    for entry in _vetted_addrinfo(parsed.host, target_port, effective_policy, dns_timeout):
        addresses[_sockaddr_ip(entry[4])] = None
    return list(addresses)


def _set_timeout(sock: socket.socket, timeout: Any) -> None:
    # Only a number or None is a real timeout. socket.create_connection's
    # default and urllib3's are both sentinels meaning "leave the default".
    if timeout is None or (isinstance(timeout, (int, float)) and not isinstance(timeout, bool)):
        sock.settimeout(timeout)


def create_guarded_connection(
    address: tuple[str, int],
    timeout: Any = socket._GLOBAL_DEFAULT_TIMEOUT,  # type: ignore[attr-defined]
    source_address: tuple[str, int] | None = None,
    socket_options: Iterable[tuple[int, int, int | bytes]] | None = None,
    *,
    policy: PolicyInput = None,
    dns_timeout: float | None = DEFAULT_DNS_TIMEOUT,
) -> socket.socket:
    """Like :func:`socket.create_connection`, but only to addresses ``policy`` permits.

    The host is resolved exactly once; every resolved address must be
    permitted or the connection is refused outright; the socket connects
    only to those vetted addresses; and the peer address is checked again
    after connecting. Raises :class:`~urlps.InvalidURLError` (code
    ``ssrf_risk``) when a connection is refused for policy reasons, and the
    usual :class:`OSError` subclasses for network failures.

    Signature-compatible with urllib3's ``create_connection``, so it can be
    installed for ``requests``/``urllib3``::

        import functools
        import urllib3.util.connection

        urllib3.util.connection.create_connection = functools.partial(
            create_guarded_connection, policy=SecurityPolicy.strict()
        )
    """
    host, port = address[0], address[1]
    effective_policy = resolve_security_policy(policy)
    # Callers pass IPv6 literals unbracketed ("::1") and may pass Unicode;
    # the policy checks want the host as the parser would store it.
    checked_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    checked_host = _canonical_host(checked_host)
    addr_info = _vetted_addrinfo(checked_host, port, effective_policy, dns_timeout)
    host_allowed_by_name = effective_policy.host_is_allowed(checked_host)

    last_error: OSError | None = None
    for family, socktype, proto, _canonname, sockaddr in addr_info:
        sock: socket.socket | None = None
        try:
            sock = socket.socket(family, socktype, proto)
            for option in socket_options or ():
                sock.setsockopt(*option)
            _set_timeout(sock, timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            peer = _sockaddr_ip(sock.getpeername())
            if not _address_permitted(effective_policy, peer, host_allowed_by_name=host_allowed_by_name):
                sock.close()
                raise _ssrf_error(f"Connected peer {peer} is a disallowed address.", checked_host)
            return sock
        except OSError as exc:
            last_error = exc
            if sock is not None:
                sock.close()
    if last_error is not None:
        raise last_error
    raise OSError("getaddrinfo returned an empty list")  # pragma: no cover - _vetted_addrinfo rejects that
