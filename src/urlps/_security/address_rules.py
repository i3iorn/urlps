"""Caller-supplied address rules: the ``allowed_addresses``/``denied_addresses`` lists.

A rule is one of:

* an IP address -- ``"10.1.2.3"``, ``"fd12::1"`` (brackets optional), or an
  :mod:`ipaddress` address object;
* a network in CIDR notation -- ``"10.1.0.0/16"``, ``"fd12:3456::/32"``, or an
  :mod:`ipaddress` network object;
* a hostname, matched exactly -- ``"build.internal"``;
* a domain with a leading dot, matching the domain *and* every subdomain --
  ``".corp.example"`` matches ``corp.example`` and ``a.b.corp.example`` but
  not ``evilcorp.example``.

Matching is done on what a host *is*, not how it is spelled: an IP rule also
matches the decimal/hex/octal and IPv4-mapped/6to4/Teredo/NAT64 spellings of
the same address, and hostnames are compared after IDNA encoding,
case-folding and trailing-dot removal.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from .._host import strip_brackets
from .._patterns import PATTERNS
from ..exceptions import SecurityPolicyError
from ._unicode import canonical_host
from .ip_utils import IpAddress, IpNetwork, _resolve_host_to_ip, embedded_ipv4, in_networks

__all__ = ["NO_RULES", "AddressList", "AddressRule"]

#: One entry of an address list as a caller may write it.
AddressRule = str | ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_network(text: str) -> IpNetwork | None:
    candidate = strip_brackets(text)
    try:
        return ipaddress.ip_network(candidate, strict=True)
    except ValueError:
        if "/" in candidate:
            # Looks like CIDR but is not valid CIDR (bad prefix, host bits
            # set). Silently treating it as a hostname would make the rule
            # match nothing, which for a deny rule means failing open.
            raise SecurityPolicyError(f"Invalid network in address rule: {text!r}") from None
        return None


@dataclass(frozen=True)
class AddressList:
    """An immutable, hashable set of address rules. Build with :meth:`from_rules`."""

    networks: tuple[IpNetwork, ...] = ()
    hostnames: frozenset[str] = frozenset()
    domains: tuple[str, ...] = ()

    @classmethod
    def from_rules(cls, rules: Iterable[AddressRule] | AddressList) -> AddressList:
        """Compile ``rules``, raising :class:`SecurityPolicyError` on any invalid one.

        Invalid rules are rejected rather than skipped: a deny rule that
        silently matches nothing is a fail-open.
        """
        if isinstance(rules, AddressList):
            return rules
        if isinstance(rules, (str, bytes)):
            raise SecurityPolicyError("Address rules must be an iterable of rules, not a single string.")

        networks: list[IpNetwork] = []
        hostnames: set[str] = set()
        domains: list[str] = []
        for rule in rules:
            if isinstance(rule, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                networks.append(rule)
                continue
            if isinstance(rule, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                networks.append(ipaddress.ip_network(rule))
                continue
            if not isinstance(rule, str):
                raise SecurityPolicyError(f"Address rules must be strings or ipaddress objects, got {rule!r}")

            text = rule.strip()
            if not text:
                raise SecurityPolicyError("Address rules must be non-empty.")
            network = _parse_network(text)
            if network is not None:
                networks.append(network)
                continue
            # "2130706433" or "0x7f000001": an IP in inet_aton spelling. As a
            # hostname rule it could never match (hosts in those spellings
            # are matched by address), so it is compiled to the address.
            literal = _resolve_host_to_ip(text.lower())
            if literal is not None:
                networks.append(ipaddress.ip_network(literal))
                continue

            is_domain = text.startswith(".")
            name = text[1:] if is_domain else text
            if "*" in name:
                raise SecurityPolicyError(
                    f"Wildcards are not supported in address rules ({rule!r}); "
                    "use a leading dot ('.example.com') to match a domain and its subdomains."
                )
            try:
                normalized = canonical_host(name)
            except ValueError as exc:  # IdnaError
                raise SecurityPolicyError(f"Invalid hostname in address rule: {rule!r}") from exc
            if not normalized or not PATTERNS["host"].fullmatch(normalized):
                raise SecurityPolicyError(f"Invalid hostname in address rule: {rule!r}")
            if is_domain:
                domains.append(normalized)
            else:
                hostnames.add(normalized)

        return cls(networks=tuple(networks), hostnames=frozenset(hostnames), domains=tuple(domains))

    def __bool__(self) -> bool:
        return bool(self.networks or self.hostnames or self.domains)

    def matches_ip(self, ip: IpAddress) -> bool:
        """Whether ``ip``, or an IPv4 address it embeds, is covered by a network rule."""
        if not self.networks:
            return False
        return any(in_networks(candidate, self.networks) for candidate in (ip, *embedded_ipv4(ip)))

    def matches_host(self, host: str) -> bool:
        """Whether ``host`` (any spelling: literal, obfuscated IP, Unicode, mixed case) is covered."""
        if not self or not host:
            return False
        ip = _resolve_host_to_ip(host.lower().rstrip("."))
        if ip is not None:
            return self.matches_ip(ip)
        if not (self.hostnames or self.domains):
            return False
        try:
            name = canonical_host(host)
        except ValueError:  # IdnaError: not a host the parser would accept either
            return False
        if name in self.hostnames:
            return True
        return any(name == domain or name.endswith("." + domain) for domain in self.domains)


#: The empty rule set, shared as the policy default.
NO_RULES = AddressList()
