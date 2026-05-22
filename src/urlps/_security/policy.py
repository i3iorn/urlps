from __future__ import annotations

from dataclasses import dataclass, replace
from functools import lru_cache
from typing import Final, Literal, Optional, Union

from urlps.exceptions import SecurityPolicyError

PolicyName = Literal["strict", "balanced", "internal"]


@dataclass(frozen=True)
class SecurityPolicy:
    """Security policy controlling how URLs are validated and sanitized.

    Each flag corresponds to a specific attack surface or normalization rule.
    Policies are immutable and safe to share across threads.

    Attributes:
        name:
            Human-readable identifier for the policy profile.

        enforce_ssrf:
            Block URL targets that could enable Server-Side Request Forgery
            (e.g., internal IPs, metadata endpoints, loopback hosts).

        enforce_path_traversal:
            Reject paths containing traversal attempts such as "../" or
            encoded variants that could escape intended directories.

        enforce_open_redirect:
            Prevent redirects to untrusted or external origins, even when
            disguised through encoding or mixed URL forms.

        enforce_mixed_scripts:
            Detect and block URLs that combine multiple scriptable schemes
            (e.g., javascript: inside data:), a common payload obfuscation tactic.

        enforce_parser_confusion:
            Guard against ambiguous or malformed URLs that exploit differences
            between URL parsers, normalizers, or downstream libraries.

        enforce_double_encoding:
            Reject URLs containing double-encoded or over-encoded characters,
            which attackers use to bypass filters or rewrite semantics.

        enforce_query_injection:
            Validate query strings to prevent injection of additional parameters,
            delimiter confusion, or malformed key/value structures.

        block_dangerous_ports:
            Disallow ports associated with high-risk services (SSH, SMTP, Redis,
            databases, etc.) to reduce SSRF pivoting and lateral movement.

        reject_credentials:
            Forbid embedding usernames or passwords in URLs, which is unsafe and
            often indicates credential leakage or phishing behavior.

        require_canonical:
            Enforce canonical URL structure (normalized host, path, percent
            encoding) to eliminate ambiguity and prevent filter bypasses.

        check_dns:
            Perform DNS resolution and apply DNS-based safety checks such as
            rebinding detection and IP canonicalization.

        check_phishing:
            Compare hostnames against a phishing-domain blocklist.

        enforce_dns_rate_limit:
            Apply rate limiting to DNS lookups to prevent resource exhaustion
            and DNS-based DoS vectors.

        dns_retries:
            Number of retry attempts for DNS lookups before failing.

        dns_backoff_base_seconds:
            Base delay used in exponential backoff between DNS retries.

        dns_backoff_jitter_seconds:
            Random jitter added to DNS retry delays to avoid synchronized retry
            storms under load.
    """
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
        """Return a strict, security-maximalist policy."""
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
        """Return a balanced policy for general-purpose usage."""
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
        """Return a relaxed policy for trusted internal environments."""
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


PolicyInput = Union[None, PolicyName, SecurityPolicy]


@lru_cache(maxsize=16)
def _resolve_named_policy(
    policy_name: PolicyName,
    check_dns: Optional[bool],
    check_phishing: Optional[bool],
) -> SecurityPolicy:
    """Resolve a named policy with optional DNS and phishing overrides."""
    if policy_name == "strict":
        base = SecurityPolicy.strict()
    elif policy_name == "balanced":
        base = SecurityPolicy.balanced()
    elif policy_name == "internal":
        base = SecurityPolicy.internal()
    else:  # pragma: no cover - guarded by PolicyName type
        raise SecurityPolicyError(f"Unsupported security policy: {policy_name!r}")

    if check_dns is None and check_phishing is None:
        return base

    effective_check_dns = base.check_dns if check_dns is None else bool(check_dns)
    effective_check_phishing = (
        base.check_phishing if check_phishing is None else bool(check_phishing)
    )

    if (
        effective_check_dns == base.check_dns
        and effective_check_phishing == base.check_phishing
    ):
        return base

    return replace(
        base,
        check_dns=effective_check_dns,
        check_phishing=effective_check_phishing,
    )


def resolve_security_policy(
    policy: PolicyInput,
    *,
    check_dns: Optional[bool] = None,
    check_phishing: Optional[bool] = None,
) -> SecurityPolicy:
    """Resolve a policy input into a concrete SecurityPolicy instance.

    Args:
        policy: None, a named policy, or an explicit SecurityPolicy.
        check_dns: Optional override for DNS checks.
        check_phishing: Optional override for phishing checks.

    Raises:
        SecurityPolicyError: If the policy name is unsupported.

    Returns:
        A fully resolved SecurityPolicy instance.
    """
    if isinstance(policy, SecurityPolicy):
        resolved = policy
    elif policy is None:
        return _resolve_named_policy("balanced", check_dns, check_phishing)
    elif policy in ("strict", "balanced", "internal"):
        return _resolve_named_policy(policy, check_dns, check_phishing)  # type: ignore[arg-type]
    else:
        raise SecurityPolicyError(f"Unsupported security policy: {policy!r}")

    if check_dns is None and check_phishing is None:
        return resolved

    effective_check_dns = resolved.check_dns if check_dns is None else bool(check_dns)
    effective_check_phishing = (
        resolved.check_phishing if check_phishing is None else bool(check_phishing)
    )

    if (
        effective_check_dns == resolved.check_dns
        and effective_check_phishing == resolved.check_phishing
    ):
        return resolved

    return replace(
        resolved,
        check_dns=effective_check_dns,
        check_phishing=effective_check_phishing,
    )


__all__ = ["SecurityPolicy", "PolicyInput", "resolve_security_policy"]
