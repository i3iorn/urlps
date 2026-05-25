"""Unified security checks for URL validation (SSRF, parser confusion, and URL hardening)."""
from __future__ import annotations

from typing import Optional
from urllib.parse import urlsplit

from .._components import SecurityFinding
from ..exceptions import ErrorCode, InvalidURLError, SecurityPolicyError
from .dns_guard import (
    DNSRateLimiterConfig,
    DNSRateLimiter,
    check_dns_rate_limit,
    check_dns_rebinding,
    check_dns_rebinding_detailed,
    get_dns_rate_limiter,
    reset_dns_rate_limiter,
)
from .ip_utils import is_malicious_ipv6_zone_id, is_private_ip, is_ssrf_risk
from .phishing_db import check_against_phishing_db, get_phishing_db_info, refresh_phishing_db
from .policy import PolicyInput, SecurityPolicy, resolve_security_policy
from .url_checks import (
    extract_host_and_path,
    get_canonical_url,
    has_credentials,
    has_double_encoding,
    has_mixed_scripts,
    has_parser_confusion,
    has_path_traversal,
    has_query_injection,
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

    split_for_double = urlsplit(normalized_url) if "://" in normalized_url else None
    double_encoding_target = (
        f"{split_for_double.path}?{split_for_double.query}" if split_for_double is not None else normalized_url
    )
    if effective_policy.enforce_double_encoding and has_double_encoding(double_encoding_target):
        findings.append(_finding("critical", ErrorCode.DOUBLE_ENCODING, "URL contains double-encoded characters.", "url"))

    if "://" not in normalized_url:
        return findings

    host, path = extract_host_and_path(normalized_url)
    split = urlsplit(normalized_url)
    query = split.query
    try:
        port = split.port
    except ValueError:
        port = None

    if host and is_malicious_ipv6_zone_id(host):
        findings.append(
            _finding("critical", ErrorCode.INVALID_IPV6_ZONE_ID, "IPv6 zone identifier contains invalid characters.", "host")
        )
    if host and effective_policy.enforce_ssrf and is_ssrf_risk(host):
        findings.append(_finding("critical", ErrorCode.SSRF_RISK, "Host poses SSRF risk and is disallowed.", "host"))
    if host and effective_policy.enforce_mixed_scripts and not is_ascii and has_mixed_scripts(host):
        findings.append(_finding("major", ErrorCode.MIXED_SCRIPTS, "URL host contains mixed Unicode scripts.", "host"))
    if path and effective_policy.enforce_path_traversal and has_path_traversal(path):
        findings.append(_finding("critical", ErrorCode.PATH_TRAVERSAL, "URL path contains path traversal patterns.", "path"))
    if path and effective_policy.enforce_open_redirect and is_open_redirect_risk(path):
        findings.append(_finding("major", ErrorCode.OPEN_REDIRECT, "URL path contains open redirect risk patterns.", "path"))
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

    effective_check_dns = effective_policy.check_dns
    if effective_check_dns and host:
        safe, dns_error = check_dns_rebinding_detailed(
            host,
            enforce_rate_limit=effective_policy.enforce_dns_rate_limit,
            retries=effective_policy.dns_retries,
            backoff_base_seconds=effective_policy.dns_backoff_base_seconds,
            backoff_jitter_seconds=effective_policy.dns_backoff_jitter_seconds,
        )
        if not safe and dns_error is not None:
            findings.append(_finding("critical", dns_error, "DNS rebinding validation failed.", "host"))

    effective_check_phishing = effective_policy.check_phishing
    if effective_check_phishing and host and check_against_phishing_db(host):
        findings.append(_finding("critical", ErrorCode.PHISHING_DOMAIN, "Host is identified as a phishing domain.", "host"))

    return findings


def validate_url_security(
    url: str,
    *,
    policy: PolicyInput = None,
    check_dns: Optional[bool] = None,
    check_phishing: Optional[bool] = None,
    raise_on_error: bool = True,
) -> list[SecurityFinding]:
    """Run policy-based security validation and optionally raise on first finding."""
    findings = collect_security_findings(url, policy=policy, check_dns=check_dns, check_phishing=check_phishing)
    if findings and raise_on_error:
        first = findings[0]
        code = ErrorCode(first.code)
        raise InvalidURLError(first.message, component=first.component, value=url, code=code)
    return findings


_CACHED_FUNCTIONS = [is_private_ip, is_ssrf_risk, has_mixed_scripts]


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
    "is_ssrf_risk",
    "is_private_ip",
    "check_dns_rebinding",
    "has_mixed_scripts",
    "has_double_encoding",
    "has_path_traversal",
    "is_open_redirect_risk",
    "has_parser_confusion",
    "is_malicious_ipv6_zone_id",
    "normalize_url_unicode",
    "is_dangerous_port",
    "extract_host_and_path",
    "validate_url_security",
    "collect_security_findings",
    "redact_url_for_logs",
    "check_dns_rebinding_detailed",
    "get_cache_info",
    "clear_caches",
    "check_against_phishing_db",
    "refresh_phishing_db",
    "get_phishing_db_info",
    "has_credentials",
    "has_query_injection",
    "has_suspicious_punycode",
    "DNSRateLimiter",
    "DNSRateLimiterConfig",
    "check_dns_rate_limit",
    "get_dns_rate_limiter",
    "reset_dns_rate_limiter",
    "is_non_canonical_url",
    "get_canonical_url",
    "SecurityPolicy",
    "PolicyInput",
    "SecurityPolicyError",
    "resolve_security_policy"
]
