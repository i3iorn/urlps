from __future__ import annotations

from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Any, Literal, Union

from .._cache_config import POLICY_CACHE_SIZE
from ..exceptions import SecurityPolicyError

PolicyName = Literal["strict", "balanced", "internal", "local"]
PolicyInput = Union[None, PolicyName, "SecurityPolicy"]
_POLICY_NAMES: tuple[str, ...] = ("strict", "balanced", "internal", "local")
_UNSET = object()


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
    # Superseded by enforce_mixed_scripts + enforce_confusable_host, which
    # decode Punycode first and work per label. Retained as an accepted
    # keyword so existing SecurityPolicy(...) calls keep constructing; it no
    # longer gates anything. Removed in 2.0.
    enforce_suspicious_punycode: bool = False
    # Whole-script confusables: a label written entirely in a non-Latin script
    # whose characters are all Latin lookalikes ("раураӏ.com"). Distinct from
    # the mixed-script check, which by definition cannot see it -- nothing is
    # mixed. On by default: the detection is precise (a label keeps any
    # character without a Latin lookalike, so ordinary non-Latin domains are
    # untouched), unlike the ASCII heuristics it replaces.
    enforce_confusable_host: bool = True
    # Bidi controls, zero-width characters and malformed Punycode in the host.
    # These have no legitimate use in a hostname.
    enforce_host_unicode_safety: bool = True
    check_dns: bool = False
    check_phishing: bool = False
    enforce_dns_rate_limit: bool = True
    dns_fail_open_on_connect_error: bool = True
    dns_retries: int = 2
    dns_backoff_base_seconds: float = 0.05
    dns_backoff_jitter_seconds: float = 0.02
    dns_rate_limiter: Any | None = None

    @classmethod
    def strict(
        cls,
        *,
        check_dns: bool = False,
        check_phishing: bool = False,
        dns_fail_open_on_connect_error: bool = False,
        dns_rate_limiter: Any | None = None,
    ) -> SecurityPolicy:
        return cls(
            name="strict",
            check_dns=check_dns,
            check_phishing=check_phishing,
            dns_fail_open_on_connect_error=dns_fail_open_on_connect_error,
            dns_rate_limiter=dns_rate_limiter,
        )

    @classmethod
    def balanced(
        cls,
        *,
        check_dns: bool = False,
        check_phishing: bool = False,
        dns_fail_open_on_connect_error: bool = True,
        dns_rate_limiter: Any | None = None,
    ) -> SecurityPolicy:
        return cls(
            name="balanced",
            check_dns=check_dns,
            check_phishing=check_phishing,
            dns_fail_open_on_connect_error=dns_fail_open_on_connect_error,
            dns_rate_limiter=dns_rate_limiter,
            block_dangerous_ports=False,
            reject_credentials=False,
            enforce_suspicious_punycode=False,
        )

    @classmethod
    def local(
        cls,
        *,
        check_dns: bool = False,
        dns_fail_open_on_connect_error: bool = True,
        dns_rate_limiter: Any | None = None,
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
            dns_fail_open_on_connect_error=dns_fail_open_on_connect_error,
            dns_rate_limiter=dns_rate_limiter,
        )

    @classmethod
    def internal(
        cls,
        *,
        check_dns: bool = False,
        enforce_ssrf: bool = True,
        dns_fail_open_on_connect_error: bool = True,
        dns_rate_limiter: Any | None = None,
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
            dns_fail_open_on_connect_error=dns_fail_open_on_connect_error,
            dns_rate_limiter=dns_rate_limiter,
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
) -> SecurityPolicy:
    """Return a new policy if overrides differ; otherwise return base."""
    effective_dns = base.check_dns if check_dns is None else bool(check_dns)
    effective_phishing = base.check_phishing if check_phishing is None else bool(check_phishing)
    effective_dns_rate_limiter = base.dns_rate_limiter if dns_rate_limiter is _UNSET else dns_rate_limiter

    if (
        effective_dns == base.check_dns
        and effective_phishing == base.check_phishing
        and effective_dns_rate_limiter is base.dns_rate_limiter
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
) -> SecurityPolicy:
    """Resolve a policy input into a concrete SecurityPolicy instance."""
    if isinstance(policy, SecurityPolicy):
        return _apply_overrides(
            policy,
            check_dns=check_dns,
            check_phishing=check_phishing,
            dns_rate_limiter=dns_rate_limiter,
        )

    if policy is None:
        base = _resolve_named_policy("strict", None, None)
        return _apply_overrides(
            base,
            check_dns=check_dns,
            check_phishing=check_phishing,
            dns_rate_limiter=dns_rate_limiter,
        )

    if policy in _POLICY_NAMES:
        base = _resolve_named_policy(policy, None, None)
        return _apply_overrides(
            base,
            check_dns=check_dns,
            check_phishing=check_phishing,
            dns_rate_limiter=dns_rate_limiter,
        )

    raise SecurityPolicyError(f"Unsupported security policy: {policy!r}")


__all__ = ["PolicyInput", "SecurityPolicy", "resolve_security_policy"]
