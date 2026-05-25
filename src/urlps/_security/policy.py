from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Literal, Optional, Union, cast

from ..exceptions import SecurityPolicyError

PolicyName = Literal["strict", "balanced", "internal"]
PolicyInput = Union[None, PolicyName, "SecurityPolicy"]


@dataclass(frozen=True)
class SecurityPolicy:
    """Immutable security policy defining URL validation and sanitization rules."""

    name: str
    enforce_ssrf: bool = True
    enforce_path_traversal: bool = True
    enforce_open_redirect: bool = True
    enforce_mixed_scripts: bool = True
    enforce_parser_confusion: bool = True
    enforce_double_encoding: bool = True
    enforce_query_injection: bool = True
    block_dangerous_ports: bool = True
    reject_credentials: bool = True
    require_canonical: bool = True
    check_dns: bool = False
    check_phishing: bool = False
    enforce_dns_rate_limit: bool = True
    dns_retries: int = 2
    dns_backoff_base_seconds: float = 0.05
    dns_backoff_jitter_seconds: float = 0.02

    @classmethod
    def strict(
        cls,
        *,
        check_dns: bool = False,
        check_phishing: bool = False,
    ) -> "SecurityPolicy":
        return cls(
            name="strict",
            check_dns=check_dns,
            check_phishing=check_phishing,
        )

    @classmethod
    def balanced(
        cls,
        *,
        check_dns: bool = False,
        check_phishing: bool = False,
    ) -> "SecurityPolicy":
        return cls(
            name="balanced",
            check_dns=check_dns,
            check_phishing=check_phishing,
            enforce_query_injection=False,
            block_dangerous_ports=False,
            reject_credentials=False,
            require_canonical=False,
        )

    @classmethod
    def internal(
        cls,
        *,
        check_dns: bool = False,
        enforce_ssrf: bool = False,
    ) -> "SecurityPolicy":
        return cls(
            name="internal",
            enforce_ssrf=enforce_ssrf,
            enforce_path_traversal=False,
            enforce_open_redirect=False,
            enforce_mixed_scripts=False,
            enforce_parser_confusion=False,
            enforce_double_encoding=False,
            enforce_query_injection=False,
            block_dangerous_ports=False,
            reject_credentials=False,
            require_canonical=False,
            check_dns=check_dns,
            check_phishing=False,
            enforce_dns_rate_limit=True,
        )

    def __str__(self) -> str:
        return f"SecurityPolicy(name={self.name!r})"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _apply_overrides(
    base: SecurityPolicy,
    *,
    check_dns: Optional[bool],
    check_phishing: Optional[bool],
) -> SecurityPolicy:
    """Return a new policy if overrides differ; otherwise return base."""
    effective_dns = base.check_dns if check_dns is None else bool(check_dns)
    effective_phishing = base.check_phishing if check_phishing is None else bool(check_phishing)

    if (
        effective_dns == base.check_dns
        and effective_phishing == base.check_phishing
    ):
        return base

    concrete_base = cast(SecurityPolicy, base)

    return SecurityPolicy(
        name=concrete_base.name,
        enforce_ssrf=concrete_base.enforce_ssrf,
        enforce_path_traversal=concrete_base.enforce_path_traversal,
        enforce_open_redirect=concrete_base.enforce_open_redirect,
        enforce_mixed_scripts=concrete_base.enforce_mixed_scripts,
        enforce_parser_confusion=concrete_base.enforce_parser_confusion,
        enforce_double_encoding=concrete_base.enforce_double_encoding,
        enforce_query_injection=concrete_base.enforce_query_injection,
        block_dangerous_ports=concrete_base.block_dangerous_ports,
        reject_credentials=concrete_base.reject_credentials,
        require_canonical=concrete_base.require_canonical,
        check_dns=effective_dns,
        check_phishing=effective_phishing,
        enforce_dns_rate_limit=concrete_base.enforce_dns_rate_limit,
        dns_retries=concrete_base.dns_retries,
        dns_backoff_base_seconds=concrete_base.dns_backoff_base_seconds,
        dns_backoff_jitter_seconds=concrete_base.dns_backoff_jitter_seconds,
    )


@lru_cache(maxsize=16)
def _resolve_named_policy(
    policy_name: PolicyName,
    check_dns: Optional[bool],
    check_phishing: Optional[bool],
) -> SecurityPolicy:
    """Resolve a named policy with optional overrides."""
    if policy_name == "strict":
        base = SecurityPolicy.strict()
    elif policy_name == "balanced":
        base = SecurityPolicy.balanced()
    elif policy_name == "internal":
        base = SecurityPolicy.internal()
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
    policy: Optional[PolicyInput | str],
    *,
    check_dns: Optional[bool] = None,
    check_phishing: Optional[bool] = None,
) -> SecurityPolicy:
    """Resolve a policy input into a concrete SecurityPolicy instance."""
    if isinstance(policy, SecurityPolicy):
        return _apply_overrides(
            policy,
            check_dns=check_dns,
            check_phishing=check_phishing,
        )

    if policy is None:
        return _resolve_named_policy("balanced", check_dns, check_phishing)

    if policy in ("strict", "balanced", "internal"):
        return _resolve_named_policy(policy, check_dns, check_phishing)  # type: ignore[arg-type]

    raise SecurityPolicyError(f"Unsupported security policy: {policy!r}")


__all__ = ["SecurityPolicy", "PolicyInput", "resolve_security_policy"]
