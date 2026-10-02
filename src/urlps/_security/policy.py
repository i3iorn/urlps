from __future__ import annotations

import warnings
from collections.abc import Iterable
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Any, Literal, Union, cast

from .._cache_config import POLICY_CACHE_SIZE
from .._validation import Validator
from ..constants import DEFAULT_DNS_DEADLINE_SECONDS, STANDARD_SCHEMES
from ..exceptions import SecurityPolicyError
from .address_rules import NO_RULES, AddressList, AddressRule
from .ip_utils import IpAddress, _is_ip_safe, is_metadata_address, is_permitted_private_ip, is_ssrf_risk

PolicyName = Literal["strict", "balanced", "internal", "local"]
PolicyInput = Union[None, PolicyName, "SecurityPolicy"]
_POLICY_NAMES: tuple[str, ...] = ("strict", "balanced", "internal", "local")
_UNSET = object()

#: What ``allowed_addresses``/``denied_addresses`` accept: a compiled
#: AddressList, or any iterable of rules (see :mod:`.address_rules`).
AddressListInput = AddressList | Iterable[AddressRule]


def _compile_schemes(schemes: AbstractSet[str] | Iterable[str]) -> frozenset[str]:
    """Lowercase and syntax-check ``allowed_schemes``; a bad entry fails at construction."""
    if isinstance(schemes, (str, bytes)):
        raise SecurityPolicyError("allowed_schemes must be a collection of schemes, not a single string.")
    entries = list(schemes)
    if not all(isinstance(scheme, str) for scheme in entries):
        raise SecurityPolicyError("allowed_schemes entries must be strings.")
    compiled = frozenset(scheme.lower() for scheme in entries)
    invalid = sorted(scheme for scheme in compiled if not Validator.is_valid_scheme(scheme))
    if invalid:
        raise SecurityPolicyError(f"Invalid scheme(s) in allowed_schemes: {', '.join(invalid)}")
    return compiled


def _deprecated_fail_open(value: bool | None, preset_default: bool) -> bool:
    """Resolve the deprecated dns_fail_open_on_connect_error preset argument."""
    if value is None:
        return preset_default
    warnings.warn(
        "dns_fail_open_on_connect_error is deprecated and has no effect: the DNS check no "
        "longer makes a verification connection. Use urlps.create_guarded_connection() "
        "for connect-time SSRF protection. The argument will be removed in a future major release.",
        DeprecationWarning,
        stacklevel=3,
    )
    return value


@dataclass(frozen=True)
class SecurityPolicy:
    """Immutable security policy defining URL validation and sanitization rules."""

    name: str
    enforce_ssrf: bool = True
    # Narrows -- never disables -- SSRF enforcement, for the local-development
    # case ("http://localhost:3000/api", "http://192.168.1.50/metrics"). When
    # True, loopback and RFC1918/ULA addresses plus the localhost/.local/
    # .localhost hostnames are permitted, while cloud metadata endpoints
    # (169.254.169.254, metadata.google.internal), the whole link-local range,
    # .internal, kubernetes service names, multicast, reserved and 0.0.0.0 stay
    # blocked. Only meaningful while enforce_ssrf is True.
    allow_private_hosts: bool = False
    enforce_path_traversal: bool = True
    enforce_open_redirect: bool = True
    enforce_mixed_scripts: bool = True
    enforce_parser_confusion: bool = True
    enforce_double_encoding: bool = True
    # Deployment policy, not a URL property: SSRF-to-internal-service is
    # already covered by enforce_ssrf, and blocking port 22/3306 on a *public*
    # host prevents nothing an attacker wants. Opt in when your egress policy
    # genuinely only permits 80/443.
    block_dangerous_ports: bool = False
    # "user:pass@host" is legal RFC 3986 and common in internal tooling.
    # Rejecting it is a policy choice, so it is opt-in; when off, a
    # non-blocking "warning" finding is still emitted (see
    # collect_security_findings) and the phishing shape that actually matters
    # ("https://apple.com@evil.com/") is caught by enforce_parser_confusion.
    reject_credentials: bool = False
    # Deprecated: accepted as a keyword for compatibility, but gates nothing.
    # See enforce_mixed_scripts and enforce_confusable_host.
    enforce_suspicious_punycode: bool = False
    # Whole-script confusables: a label written entirely in a non-Latin script
    # whose characters are all Latin lookalikes ("раураӏ.com"). Distinct from
    # the mixed-script check, which by definition cannot see it -- nothing is
    # mixed.
    enforce_confusable_host: bool = True
    # Bidi controls, zero-width characters and malformed Punycode in the host.
    # These have no legitimate use in a hostname.
    enforce_host_unicode_safety: bool = True
    check_dns: bool = False
    check_phishing: bool = False
    # When check_phishing is on and the database cannot be loaded, reject the
    # URL instead of accepting it with a warning finding.
    phishing_fail_closed: bool = False
    enforce_dns_rate_limit: bool = True
    # Deprecated: gates nothing. It governed a post-resolution "verification
    # connect" that has been removed (it re-checked the address just resolved,
    # so it could not detect rebinding). See urlps.create_guarded_connection.
    dns_fail_open_on_connect_error: bool = True
    dns_retries: int = 2
    dns_backoff_base_seconds: float = 0.05
    dns_backoff_jitter_seconds: float = 0.02
    # Wall-clock bound on one DNS check across retries and backoff.
    dns_deadline_seconds: float = DEFAULT_DNS_DEADLINE_SECONDS
    dns_rate_limiter: Any | None = None
    # Caller-supplied address rules, applied to the host and to every
    # DNS-resolved address. Each rule is an IP, a CIDR network, a hostname, or
    # a ".domain" (the domain and all its subdomains); see
    # urlps._security.address_rules. A denied match always rejects -- even
    # with enforce_ssrf=False -- and wins over an allowed match. An allowed
    # match exempts the host from the built-in SSRF classification; allowing
    # a hostname also trusts what it resolves to, except cloud metadata
    # addresses, which only an explicit IP/network rule can allow.
    allowed_addresses: AddressListInput = NO_RULES
    denied_addresses: AddressListInput = NO_RULES
    # The schemes a URL may have: the standard web/file-transfer schemes by
    # default. allowed_schemes={"https"} narrows that; allow_custom_scheme
    # accepts any well-formed scheme (including javascript:, data:, file:),
    # which is what parse_url(..., allow_custom_scheme=True) sets.
    allowed_schemes: AbstractSet[str] = STANDARD_SCHEMES
    allow_custom_scheme: bool = False

    def __post_init__(self) -> None:
        # Compile here so an invalid rule fails at policy construction, not on
        # the first URL that happens to reach it.
        object.__setattr__(self, "allowed_addresses", AddressList.from_rules(self.allowed_addresses))
        object.__setattr__(self, "denied_addresses", AddressList.from_rules(self.denied_addresses))
        object.__setattr__(self, "allowed_schemes", _compile_schemes(self.allowed_schemes))
        if self.enforce_suspicious_punycode:
            warnings.warn(
                "SecurityPolicy.enforce_suspicious_punycode is deprecated and "
                "gates nothing; homograph detection runs unconditionally via "
                "enforce_mixed_scripts and enforce_confusable_host. This field "
                "will be removed in a future major release.",
                DeprecationWarning,
                stacklevel=2,
            )

    @property
    def _allowed(self) -> AddressList:
        return cast(AddressList, self.allowed_addresses)

    @property
    def _denied(self) -> AddressList:
        return cast(AddressList, self.denied_addresses)

    def host_is_denied(self, host: str) -> bool:
        """Whether ``host`` (in any spelling) matches a ``denied_addresses`` rule."""
        return self._denied.matches_host(host)

    def host_is_allowed(self, host: str) -> bool:
        """Whether ``host`` matches an ``allowed_addresses`` rule and no denied one."""
        return not self.host_is_denied(host) and self._allowed.matches_host(host)

    def host_is_ssrf_risk(self, host: str) -> bool:
        """The SSRF verdict for ``host`` under this policy's rules.

        Denied rules first, then allowed rules, then the built-in
        classification (narrowed by ``allow_private_hosts``). Does not consult
        ``enforce_ssrf``; callers decide whether the built-in verdict applies.
        """
        if self.host_is_denied(host):
            return True
        if self._allowed.matches_host(host):
            return False
        return is_ssrf_risk(host, allow_private=self.allow_private_hosts)

    def ip_is_permitted(
        self, ip: IpAddress, *, host_allowed_by_name: bool = False, allow_private: bool = False
    ) -> bool:
        """Whether a resolved/peer address may be connected to under this policy.

        ``host_allowed_by_name`` is True when the hostname being resolved
        matched an allowed rule: its addresses are then trusted, except
        cloud metadata addresses and anything denied. ``allow_private``
        applies the ``local`` policy's narrowing (loopback/private permitted,
        metadata and link-local never) -- the connect-time guard passes
        ``allow_private_hosts``; the parse-time DNS check deliberately does not.
        """
        if self._denied.matches_ip(ip):
            return False
        if self._allowed.matches_ip(ip):
            return True
        if host_allowed_by_name:
            return not is_metadata_address(ip)
        if allow_private and is_permitted_private_ip(ip):
            return True
        return _is_ip_safe(ip)

    @classmethod
    def strict(
        cls,
        *,
        check_dns: bool = False,
        check_phishing: bool = False,
        phishing_fail_closed: bool = False,
        dns_fail_open_on_connect_error: bool | None = None,
        dns_rate_limiter: Any | None = None,
        allowed_addresses: AddressListInput = (),
        denied_addresses: AddressListInput = (),
    ) -> SecurityPolicy:
        return cls(
            name="strict",
            check_dns=check_dns,
            check_phishing=check_phishing,
            phishing_fail_closed=phishing_fail_closed,
            dns_fail_open_on_connect_error=_deprecated_fail_open(dns_fail_open_on_connect_error, False),
            dns_rate_limiter=dns_rate_limiter,
            allowed_addresses=allowed_addresses,
            denied_addresses=denied_addresses,
        )

    @classmethod
    def balanced(
        cls,
        *,
        check_dns: bool = False,
        check_phishing: bool = False,
        phishing_fail_closed: bool = False,
        dns_fail_open_on_connect_error: bool | None = None,
        dns_rate_limiter: Any | None = None,
        allowed_addresses: AddressListInput = (),
        denied_addresses: AddressListInput = (),
    ) -> SecurityPolicy:
        return cls(
            name="balanced",
            check_dns=check_dns,
            check_phishing=check_phishing,
            phishing_fail_closed=phishing_fail_closed,
            dns_fail_open_on_connect_error=_deprecated_fail_open(dns_fail_open_on_connect_error, True),
            dns_rate_limiter=dns_rate_limiter,
            block_dangerous_ports=False,
            reject_credentials=False,
            enforce_suspicious_punycode=False,
            allowed_addresses=allowed_addresses,
            denied_addresses=denied_addresses,
        )

    @classmethod
    def local(
        cls,
        *,
        check_dns: bool = False,
        dns_fail_open_on_connect_error: bool | None = None,
        dns_rate_limiter: Any | None = None,
        allowed_addresses: AddressListInput = (),
        denied_addresses: AddressListInput = (),
    ) -> SecurityPolicy:
        """Local development: like ``internal``, but loopback/private hosts are allowed.

        SSRF enforcement stays *on* and is merely narrowed -- cloud metadata
        endpoints, the link-local range, ``.internal`` and kubernetes service
        names remain blocked, so this is not a blanket "turn security off".
        """
        return cls(
            name="local",
            enforce_ssrf=True,
            allow_private_hosts=True,
            enforce_path_traversal=False,
            enforce_open_redirect=False,
            enforce_mixed_scripts=False,
            enforce_parser_confusion=False,
            enforce_double_encoding=False,
            block_dangerous_ports=False,
            reject_credentials=False,
            enforce_suspicious_punycode=False,
            enforce_confusable_host=False,
            enforce_host_unicode_safety=False,
            check_dns=check_dns,
            check_phishing=False,
            enforce_dns_rate_limit=True,
            dns_fail_open_on_connect_error=_deprecated_fail_open(dns_fail_open_on_connect_error, True),
            dns_rate_limiter=dns_rate_limiter,
            allowed_addresses=allowed_addresses,
            denied_addresses=denied_addresses,
        )

    @classmethod
    def internal(
        cls,
        *,
        check_dns: bool = False,
        enforce_ssrf: bool = True,
        dns_fail_open_on_connect_error: bool | None = None,
        dns_rate_limiter: Any | None = None,
        allowed_addresses: AddressListInput = (),
        denied_addresses: AddressListInput = (),
    ) -> SecurityPolicy:
        """Trusted/internal input: heuristics off, but SSRF still enforced.

        ``enforce_ssrf`` defaults to True: a preset whose name suggests
        "internal network" must not silently permit a request to
        169.254.169.254. Pass ``enforce_ssrf=False`` to opt out explicitly, or
        use :meth:`local` for the development case, which permits loopback and
        RFC1918 while still blocking metadata endpoints.
        """
        return cls(
            name="internal",
            enforce_ssrf=enforce_ssrf,
            enforce_path_traversal=False,
            enforce_open_redirect=False,
            enforce_mixed_scripts=False,
            enforce_parser_confusion=False,
            enforce_double_encoding=False,
            block_dangerous_ports=False,
            reject_credentials=False,
            enforce_suspicious_punycode=False,
            enforce_confusable_host=False,
            enforce_host_unicode_safety=False,
            check_dns=check_dns,
            check_phishing=False,
            enforce_dns_rate_limit=True,
            dns_fail_open_on_connect_error=_deprecated_fail_open(dns_fail_open_on_connect_error, True),
            dns_rate_limiter=dns_rate_limiter,
            allowed_addresses=allowed_addresses,
            denied_addresses=denied_addresses,
        )

    def __str__(self) -> str:
        return f"SecurityPolicy(name={self.name!r})"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _apply_overrides(
    base: SecurityPolicy,
    *,
    check_dns: bool | None,
    check_phishing: bool | None,
    dns_rate_limiter: Any = _UNSET,
    allow_custom_scheme: bool | None = None,
) -> SecurityPolicy:
    """Return a new policy if overrides differ; otherwise return base."""
    effective_dns = base.check_dns if check_dns is None else bool(check_dns)
    effective_phishing = base.check_phishing if check_phishing is None else bool(check_phishing)
    # Only ever widens: allow_custom_scheme=False at an entry point is its
    # default, not a request to narrow a policy that allows custom schemes.
    effective_custom_scheme = base.allow_custom_scheme or bool(allow_custom_scheme)
    # None means "not provided", like check_dns=None: the entry points pass
    # their own dns_rate_limiter=None default through here, and treating it as
    # an override silently dropped a limiter injected on the policy, moving
    # that caller onto the shared process-global limiter.
    effective_dns_rate_limiter = (
        base.dns_rate_limiter if dns_rate_limiter is _UNSET or dns_rate_limiter is None else dns_rate_limiter
    )

    if (
        effective_dns == base.check_dns
        and effective_phishing == base.check_phishing
        and effective_dns_rate_limiter is base.dns_rate_limiter
        and effective_custom_scheme == base.allow_custom_scheme
    ):
        return base

    # dataclasses.replace() rather than re-listing every field by hand: the
    # manual version silently dropped any field added later back to its
    # default, which in a security policy means silently disabling a check.
    return replace(
        base,
        check_dns=effective_dns,
        check_phishing=effective_phishing,
        dns_rate_limiter=effective_dns_rate_limiter,
        allow_custom_scheme=effective_custom_scheme,
    )


@lru_cache(maxsize=POLICY_CACHE_SIZE)
def _resolve_named_policy(
    policy_name: PolicyName,
    check_dns: bool | None,
    check_phishing: bool | None,
) -> SecurityPolicy:
    """Resolve a named policy with optional overrides."""
    if policy_name == "strict":
        base = SecurityPolicy.strict()
    elif policy_name == "balanced":
        base = SecurityPolicy.balanced()
    elif policy_name == "internal":
        base = SecurityPolicy.internal()
    elif policy_name == "local":
        base = SecurityPolicy.local()
    else:
        raise SecurityPolicyError(f"Unsupported security policy: {policy_name!r}")

    return _apply_overrides(
        base,
        check_dns=check_dns,
        check_phishing=check_phishing,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def resolve_security_policy(
    policy: PolicyInput | str | None,
    *,
    check_dns: bool | None = None,
    check_phishing: bool | None = None,
    dns_rate_limiter: Any = _UNSET,
    allow_custom_scheme: bool | None = None,
) -> SecurityPolicy:
    """Resolve a policy input into a concrete SecurityPolicy instance."""
    if isinstance(policy, SecurityPolicy):
        return _apply_overrides(
            policy,
            check_dns=check_dns,
            check_phishing=check_phishing,
            dns_rate_limiter=dns_rate_limiter,
            allow_custom_scheme=allow_custom_scheme,
        )

    if policy is None:
        base = _resolve_named_policy("strict", None, None)
        return _apply_overrides(
            base,
            check_dns=check_dns,
            check_phishing=check_phishing,
            dns_rate_limiter=dns_rate_limiter,
            allow_custom_scheme=allow_custom_scheme,
        )

    if policy in _POLICY_NAMES:
        base = _resolve_named_policy(cast(PolicyName, policy), None, None)
        return _apply_overrides(
            base,
            check_dns=check_dns,
            check_phishing=check_phishing,
            dns_rate_limiter=dns_rate_limiter,
            allow_custom_scheme=allow_custom_scheme,
        )

    raise SecurityPolicyError(f"Unsupported security policy: {policy!r}")


__all__ = ["AddressListInput", "PolicyInput", "SecurityPolicy", "resolve_security_policy"]
