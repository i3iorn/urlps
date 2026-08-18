"""Unified security checks for URL validation (SSRF, parser confusion, and URL hardening)."""
from __future__ import annotations

from typing import Any, List, Optional
from urllib.parse import urlsplit

from .._components import SecurityFinding
from ..exceptions import ErrorCode, InvalidURLError, SecurityPolicyError
from .dns_guard import (
    DNSRateLimiter,
    DNSRateLimiterConfig,
    check_dns_rate_limit,
    check_dns_rebinding,
    check_dns_rebinding_detailed,
    get_dns_rate_limiter,
    reset_dns_rate_limiter,
)
from .ip_utils import is_malicious_ipv6_zone_id, is_private_ip, is_ssrf_risk
from .phishing_db import (
    check_against_phishing_db,
    check_against_phishing_db_detailed,
    get_phishing_db_info,
    refresh_phishing_db,
)
from .policy import PolicyInput, SecurityPolicy, resolve_security_policy
from .url_checks import (
    extract_host_and_path,
    find_authority_marker,
    get_canonical_url,
    has_credentials,
    has_double_encoding,
    has_mixed_scripts,
    has_parser_confusion,
    has_path_traversal,
    has_query_injection,
    has_scheme_authority,
    has_suspicious_punycode,
    is_dangerous_port,
    is_non_canonical_url,
    is_open_redirect_risk,
    normalize_url_unicode,
    redact_url_for_logs,
)


def _finding(severity: str, code: ErrorCode, message: str, component: Optional[str]) -> SecurityFinding:
    """Create a normalized security finding object."""
    return SecurityFinding(severity=severity, code=code.value, message=message, component=component)


def collect_security_findings(
    url: str,
    *,
    policy: PolicyInput = None,
    check_dns: Optional[bool] = None,
    check_phishing: Optional[bool] = None,
) -> list[SecurityFinding]:
    """Collect policy-aware security findings without raising exceptions."""
    effective_policy = resolve_security_policy(policy, check_dns=check_dns, check_phishing=check_phishing)
    findings: list[SecurityFinding] = []

    normalized_url = normalize_url_unicode(url)

    is_ascii = True
    try:
        normalized_url.encode("ascii")
    except (UnicodeEncodeError, UnicodeDecodeError):
        is_ascii = False

    has_authority_syntax = has_scheme_authority(normalized_url)
    split_for_double = urlsplit(normalized_url) if has_authority_syntax else None
    double_encoding_target = (
        f"{split_for_double.path}?{split_for_double.query}" if split_for_double is not None else normalized_url
    )
    if effective_policy.enforce_double_encoding and has_double_encoding(double_encoding_target):
        findings.append(_finding("critical", ErrorCode.DOUBLE_ENCODING, "URL contains double-encoded characters.", "url"))

    if not has_authority_syntax:
        return findings

    host, path = extract_host_and_path(normalized_url)
    split = urlsplit(normalized_url)
    query = split.query
    try:
        port = split.port
    except ValueError:
        port = None

    # --- Host-related checks ---
    if host:
        if is_malicious_ipv6_zone_id(host):
            findings.append(
                _finding("critical", ErrorCode.INVALID_IPV6_ZONE_ID, "IPv6 zone identifier contains invalid characters.", "host")
            )
        if effective_policy.enforce_ssrf and is_ssrf_risk(host):
            findings.append(_finding("critical", ErrorCode.SSRF_RISK, "Host poses SSRF risk and is disallowed.", "host"))
        if effective_policy.enforce_mixed_scripts and not is_ascii and has_mixed_scripts(host):
            findings.append(_finding("major", ErrorCode.MIXED_SCRIPTS, "URL host contains mixed Unicode scripts.", "host"))

    # --- Path-related checks ---
    if path:
        if effective_policy.enforce_path_traversal and has_path_traversal(path):
            findings.append(_finding("critical", ErrorCode.PATH_TRAVERSAL, "URL path contains path traversal patterns.", "path"))
        if effective_policy.enforce_open_redirect and is_open_redirect_risk(path):
            findings.append(_finding("major", ErrorCode.OPEN_REDIRECT, "URL path contains open redirect risk patterns.", "path"))

    # --- URL structural checks ---
    if effective_policy.enforce_parser_confusion and has_parser_confusion(normalized_url):
        findings.append(
            _finding(
                "critical",
                ErrorCode.PARSER_CONFUSION,
                "URL contains ambiguous syntax that could cause parser confusion.",
                "url",
            )
        )
    if effective_policy.enforce_query_injection and query and has_query_injection(query):
        findings.append(_finding("major", ErrorCode.QUERY_INJECTION, "URL query contains injection-like patterns.", "query"))
    if effective_policy.reject_credentials and has_credentials(normalized_url):
        findings.append(_finding("major", ErrorCode.CREDENTIALS_IN_URL, "URL credentials are disallowed by policy.", "userinfo"))
    if effective_policy.block_dangerous_ports and is_dangerous_port(port, block_dangerous_ports=True):
        findings.append(_finding("major", ErrorCode.DANGEROUS_PORT, "URL uses a blocked dangerous port.", "port"))
    if effective_policy.require_canonical and is_non_canonical_url(normalized_url):
        findings.append(_finding("major", ErrorCode.NON_CANONICAL_URL, "URL is not in canonical form.", "url"))

    # --- DNS checks ---
    effective_check_dns = effective_policy.check_dns
    if effective_check_dns and host:
        safe, dns_error = check_dns_rebinding_detailed(
            host,
            enforce_rate_limit=effective_policy.enforce_dns_rate_limit,
            retries=effective_policy.dns_retries,
            backoff_base_seconds=effective_policy.dns_backoff_base_seconds,
            backoff_jitter_seconds=effective_policy.dns_backoff_jitter_seconds,
            fail_open_on_connect_error=effective_policy.dns_fail_open_on_connect_error,
            limiter=effective_policy.dns_rate_limiter,
        )
        if not safe and dns_error is not None:
            findings.append(_finding("critical", dns_error, "DNS rebinding validation failed.", "host"))

    effective_check_phishing = effective_policy.check_phishing
    if effective_check_phishing and host:
        is_phishing, db_available = check_against_phishing_db_detailed(host)
        if is_phishing:
            findings.append(
                _finding(
                    "critical",
                    ErrorCode.PHISHING_DOMAIN,
                    "Host is identified as a phishing domain.",
                    "host",
                )
            )
        elif not db_available:
            # The caller opted into phishing checking and received none.
            # Reporting a clean result here would be a lie, so surface it as a
            # warning finding rather than failing silently. It is not
            # "critical" because it is a degraded check, not a detected threat;
            # callers that require the check can treat it as fatal.
            findings.append(
                _finding(
                    "warning",
                    ErrorCode.PHISHING_DB_UNAVAILABLE,
                    "Phishing database unavailable; host was not checked.",
                    "host",
                )
            )

    return findings


# Severities that represent a detected problem with the URL itself. Anything
# below this is advisory -- it is reported in findings but does not reject the
# URL, because a degraded check is not the same as a failed one.
BLOCKING_SEVERITIES = frozenset({"critical", "major"})


def validate_url_security(
    url: str,
    *,
    policy: PolicyInput = None,
    check_dns: Optional[bool] = None,
    check_phishing: Optional[bool] = None,
    raise_on_error: bool = True,
) -> list[SecurityFinding]:
    """Run policy-based security validation, raising on the first blocking finding.

    All findings are returned regardless; only blocking severities raise. This
    lets an advisory finding (for example, "the phishing database could not be
    downloaded, so the host was not checked") reach the caller without turning
    a degraded optional check into a hard parse failure.
    """
    findings = collect_security_findings(url, policy=policy, check_dns=check_dns, check_phishing=check_phishing)
    if raise_on_error:
        for finding in findings:
            if finding.severity in BLOCKING_SEVERITIES:
                code = ErrorCode(finding.code)
                raise InvalidURLError(
                    finding.message, component=finding.component, value=url, code=code
                )
    return findings


_CACHED_FUNCTIONS: List[Any] = [
    is_private_ip, is_ssrf_risk, has_mixed_scripts,
    has_parser_confusion, find_authority_marker,
]


def get_cache_info() -> dict:
    """Get statistics about security check caches."""
    return {
        f.__wrapped__.__name__: {
            "hits": f.cache_info().hits,
            "misses": f.cache_info().misses,
            "maxsize": f.cache_info().maxsize,
            "currsize": f.cache_info().currsize,
        }
        for f in _CACHED_FUNCTIONS
        if hasattr(f, "cache_info")
    }


def clear_caches() -> dict:
    """Clear all security caches and return previous sizes."""
    previous = {f.__wrapped__.__name__: f.cache_info().currsize for f in _CACHED_FUNCTIONS if hasattr(f, "cache_info")}
    for cached in _CACHED_FUNCTIONS:
        if hasattr(cached, "cache_clear"):
            cached.cache_clear()
    return previous


__all__ = [
    "DNSRateLimiter",
    "DNSRateLimiterConfig",
    "PolicyInput",
    "SecurityPolicy",
    "SecurityPolicyError",
    "check_against_phishing_db",
    "check_against_phishing_db_detailed",
    "check_dns_rate_limit",
    "check_dns_rebinding",
    "check_dns_rebinding_detailed",
    "clear_caches",
    "collect_security_findings",
    "extract_host_and_path",
    "get_cache_info",
    "get_canonical_url",
    "get_dns_rate_limiter",
    "get_phishing_db_info",
    "has_credentials",
    "has_double_encoding",
    "has_mixed_scripts",
    "has_parser_confusion",
    "has_path_traversal",
    "has_query_injection",
    "has_scheme_authority",
    "has_suspicious_punycode",
    "is_dangerous_port",
    "is_malicious_ipv6_zone_id",
    "is_non_canonical_url",
    "is_open_redirect_risk",
    "is_private_ip",
    "is_ssrf_risk",
    "normalize_url_unicode",
    "redact_url_for_logs",
    "refresh_phishing_db",
    "reset_dns_rate_limiter",
    "resolve_security_policy",
    "validate_url_security"
]
