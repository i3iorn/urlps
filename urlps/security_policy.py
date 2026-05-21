from __future__ import annotations

from dataclasses import dataclass
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
        resolved = SecurityPolicy.balanced()
    elif policy == "strict":
        resolved = SecurityPolicy.strict()
    elif policy == "balanced":
        resolved = SecurityPolicy.balanced()
    elif policy == "internal":
        resolved = SecurityPolicy.internal()
    else:
        raise ValueError(f"Unsupported security policy: {policy!r}")

    if check_dns is not None or check_phishing is not None:
        effective_check_dns = resolved.check_dns if check_dns is None else bool(check_dns)
        effective_check_phishing = resolved.check_phishing if check_phishing is None else bool(check_phishing)
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
            check_dns=effective_check_dns,
            check_phishing=effective_check_phishing,
            enforce_dns_rate_limit=resolved.enforce_dns_rate_limit,
            dns_retries=resolved.dns_retries,
            dns_backoff_base_seconds=resolved.dns_backoff_base_seconds,
            dns_backoff_jitter_seconds=resolved.dns_backoff_jitter_seconds,
        )

    return resolved


__all__ = ["SecurityPolicy", "PolicyInput", "resolve_security_policy"]

