from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Optional, Union


@dataclass(frozen=True)
class SecurityPolicy:
    """Configurable security policy for URL parsing and validation."""

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
    def strict(cls, *, check_dns: bool = False, check_phishing: bool = False) -> "SecurityPolicy":
        return cls(name="strict", check_dns=check_dns, check_phishing=check_phishing)

    @classmethod
    def balanced(cls, *, check_dns: bool = False, check_phishing: bool = False) -> "SecurityPolicy":
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
    def internal(cls, *, check_dns: bool = False, enforce_ssrf: bool = False) -> "SecurityPolicy":
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


PolicyInput = Union[None, str, SecurityPolicy]


@lru_cache(maxsize=16)
def _resolve_named_policy(policy_name: str, check_dns: Optional[bool], check_phishing: Optional[bool]) -> SecurityPolicy:
    if policy_name == "strict":
        base = SecurityPolicy.strict()
    elif policy_name == "balanced":
        base = SecurityPolicy.balanced()
    elif policy_name == "internal":
        base = SecurityPolicy.internal()
    else:
        raise ValueError(f"Unsupported security policy: {policy_name!r}")

    if check_dns is None and check_phishing is None:
        return base

    if check_dns is None:
        effective_check_dns = base.check_dns
    else:
        effective_check_dns = bool(check_dns)
    if check_phishing is None:
        effective_check_phishing = base.check_phishing
    else:
        effective_check_phishing = bool(check_phishing)
    if effective_check_dns == base.check_dns and effective_check_phishing == base.check_phishing:
        return base

    return SecurityPolicy(
        name=base.name,
        enforce_ssrf=base.enforce_ssrf,
        enforce_path_traversal=base.enforce_path_traversal,
        enforce_open_redirect=base.enforce_open_redirect,
        enforce_mixed_scripts=base.enforce_mixed_scripts,
        enforce_parser_confusion=base.enforce_parser_confusion,
        enforce_double_encoding=base.enforce_double_encoding,
        enforce_query_injection=base.enforce_query_injection,
        block_dangerous_ports=base.block_dangerous_ports,
        reject_credentials=base.reject_credentials,
        require_canonical=base.require_canonical,
        check_dns=bool(effective_check_dns),
        check_phishing=bool(effective_check_phishing),
        enforce_dns_rate_limit=base.enforce_dns_rate_limit,
        dns_retries=base.dns_retries,
        dns_backoff_base_seconds=base.dns_backoff_base_seconds,
        dns_backoff_jitter_seconds=base.dns_backoff_jitter_seconds,
    )


def resolve_security_policy(
    policy: PolicyInput,
    *,
    check_dns: Optional[bool] = None,
    check_phishing: Optional[bool] = None,
) -> SecurityPolicy:
    """Resolve a policy input into a concrete SecurityPolicy instance."""

    if isinstance(policy, SecurityPolicy):
        resolved = policy
    elif policy is None:
        return _resolve_named_policy("balanced", check_dns, check_phishing)
    elif policy in {"strict", "balanced", "internal"}:
        return _resolve_named_policy(policy, check_dns, check_phishing)
    else:
        raise ValueError(f"Unsupported security policy: {policy!r}")

    if check_dns is None and check_phishing is None:
        return resolved

    if check_dns is None:
        effective_check_dns = resolved.check_dns
    else:
        effective_check_dns = bool(check_dns)
    if check_phishing is None:
        effective_check_phishing = resolved.check_phishing
    else:
        effective_check_phishing = bool(check_phishing)
    if effective_check_dns == resolved.check_dns and effective_check_phishing == resolved.check_phishing:
        return resolved

    return SecurityPolicy(
        name=resolved.name,
        enforce_ssrf=resolved.enforce_ssrf,
        enforce_path_traversal=resolved.enforce_path_traversal,
        enforce_open_redirect=resolved.enforce_open_redirect,
        enforce_mixed_scripts=resolved.enforce_mixed_scripts,
        enforce_parser_confusion=resolved.enforce_parser_confusion,
        enforce_double_encoding=resolved.enforce_double_encoding,
        enforce_query_injection=resolved.enforce_query_injection,
        block_dangerous_ports=resolved.block_dangerous_ports,
        reject_credentials=resolved.reject_credentials,
        require_canonical=resolved.require_canonical,
        check_dns=bool(effective_check_dns),
        check_phishing=bool(effective_check_phishing),
        enforce_dns_rate_limit=resolved.enforce_dns_rate_limit,
        dns_retries=resolved.dns_retries,
        dns_backoff_base_seconds=resolved.dns_backoff_base_seconds,
        dns_backoff_jitter_seconds=resolved.dns_backoff_jitter_seconds,
    )



__all__ = ["SecurityPolicy", "PolicyInput", "resolve_security_policy"]

