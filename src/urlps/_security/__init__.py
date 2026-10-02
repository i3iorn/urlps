"""Unified security checks for URL validation (SSRF, parser confusion, and URL hardening)."""

from __future__ import annotations

from typing import NamedTuple
from urllib.parse import SplitResult, urlsplit

from .._cache_config import cache_info
from .._cache_config import clear_caches as clear_registered_caches
from .._components import SecurityFinding
from .._redaction import redact_component, redact_url_for_logs
from .._unicode import canonical_host
from .._validation import scheme_rejection
from ..exceptions import (
    DNSConnectionError,
    DNSRateLimitError,
    DNSResolutionError,
    ErrorCode,
    InvalidURLError,
    SecurityPolicyError,
    UnsupportedSchemeError,
)
from .dns_guard import (
    DNSCacheConfig,
    DNSCheckOptions,
    DNSCheckResult,
    DNSRateLimiter,
    DNSRateLimiterConfig,
    DNSResolutionCache,
    check_dns_rate_limit,
    check_dns_rebinding,
    check_dns_rebinding_detailed,
    check_host_resolution,
    get_dns_rate_limiter,
    reset_dns_rate_limiter,
)
from .host_analysis import analyze_host
from .ip_utils import is_malicious_ipv6_zone_id, is_private_ip, is_ssrf_risk
from .phishing_db import (
    check_against_phishing_db,
    check_against_phishing_db_detailed,
    get_phishing_db_info,
    refresh_phishing_db,
)
from .policy import (
    PolicyInput,
    SecurityPolicy,
    resolve_security_policy,
)
from .services import DEFAULT_SERVICES, PhishingFeed, SecurityServices
from .url_checks import (
    extract_host_and_path,
    get_canonical_url,
    has_credentials,
    has_double_encoding,
    has_mixed_scripts,
    has_parser_confusion,
    has_path_traversal,
    has_scheme_authority,
    has_suspicious_punycode,
    is_commonly_abused_port,
    is_dangerous_port,
    is_open_redirect_risk,
    normalize_url_unicode,
)

#: Per-code hint naming the way out, for the rejections a caller is most
#: likely to hit on legitimate input. Kept as data next to the codes rather
#: than inline at each call site so the wording stays consistent.
_REMEDIATION_BY_CODE: dict[ErrorCode, str] = {
    ErrorCode.SSRF_RISK: (
        "If this is an intentional local or internal URL, use parse_url_local() "
        'or policy="local", which still blocks cloud metadata endpoints. To permit '
        "specific hosts or networks, add them to the policy's allowed_addresses. To "
        "turn SSRF enforcement off entirely, pass "
        "SecurityPolicy.internal(enforce_ssrf=False)."
    ),
    ErrorCode.DANGEROUS_PORT: (
        "Port blocking is opt-in; it is enabled on this policy. Use "
        'policy="balanced" or SecurityPolicy.strict(block_dangerous_ports=False) '
        "if this port is expected."
    ),
    ErrorCode.DNS_RATE_LIMITED: (
        "Retryable: see retry_after. The limiter only counts real lookups (cached "
        "answers are free); inject a DNSRateLimiter per tenant so one tenant cannot "
        "spend another's budget."
    ),
    ErrorCode.PHISHING_DB_UNAVAILABLE: (
        "The phishing feed could not be downloaded; see get_phishing_db_info()['last_error']. "
        "A policy with phishing_fail_closed=True rejects the URL in this case; otherwise it is a warning."
    ),
    ErrorCode.CREDENTIALS_IN_URL: (
        "Credentials in a URL are legal but discouraged. Use "
        'policy="balanced" to allow them, and URL.redacted() or '
        "URL.as_string(mask_password=True) when logging."
    ),
    ErrorCode.MIXED_SCRIPT_LABEL: (
        'If this domain is legitimate, use policy="internal" or set enforce_mixed_scripts=False.'
    ),
    ErrorCode.CONFUSABLE_HOST: (
        'If this domain is legitimate, use policy="internal" or set enforce_confusable_host=False.'
    ),
}


_DNS_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.SSRF_RISK: "Host resolves to a disallowed address.",
    ErrorCode.DNS_RATE_LIMITED: "DNS lookup rate limit reached; the host was not checked.",
    ErrorCode.DNS_RESOLUTION_FAILED: "Host could not be resolved.",
    ErrorCode.DNS_CONNECTION_FAILED: "DNS resolution timed out or failed.",
}


def _finding(severity: str, code: ErrorCode, message: str, component: str | None) -> SecurityFinding:
    """Create a normalized security finding object."""
    return SecurityFinding(
        severity=severity,
        code=code.value,
        message=message,
        component=component,
        remediation=_REMEDIATION_BY_CODE.get(code),
    )


class ParsedComponents(NamedTuple):
    """The components exactly as the parser produced them.

    This is what ``URL.host``/``URL.port``/``URL.userinfo``/``URL.path``
    expose and what ``str(url)`` serializes, so it -- not a re-extraction
    from the raw string -- is what the checks must validate. Validating a
    second, independently parsed copy is a parser differential:
    ``http://169.254.169.254?`` and ``127.0.0.1`` written with ideographic
    full stops (U+3002) both passed the SSRF check, while the parser handed
    the caller a metadata/loopback host. The path matters for the same
    reason: ``/.//evil.com`` has no leading ``//`` as written, but
    normalizes to ``//evil.com``, a protocol-relative redirect target.
    """

    host: str | None
    port: int | None
    userinfo: str | None
    path: str | None = None
    scheme: str | None = None


def _canonical_host(raw_host: str) -> str:
    """Return ``raw_host`` in the form the parser stores: IDNA-encoded, then normalized.

    A host IDNA rejects is returned as-is; the parser refuses it anyway, and
    the raw text is still worth running the checks on.
    """
    try:
        return canonical_host(raw_host)
    except ValueError:  # IdnaError; caught by its base so a reloaded uts46 module still matches
        return raw_host


def _explicit_port(split: SplitResult) -> int | None:
    try:
        return split.port
    except ValueError:
        return None


class _CheckContext(NamedTuple):
    """What every check reads: the policy, and each component in every spelling that matters."""

    policy: SecurityPolicy
    #: Resolver, caches, limiter and phishing feed.
    services: SecurityServices
    #: The raw URL, NFC-normalized.
    url: str
    #: Whether the URL has an authority at all (otherwise only the
    #: scheme and encoding checks apply).
    has_authority: bool
    scheme: str | None
    #: The authoritative host: the parser's when given, else extracted.
    host: str
    #: Every spelling of the host, authoritative one first.
    host_spellings: tuple[str, ...]
    port: int | None
    #: The raw path (what the heuristics were written for) and the parsed one.
    path_spellings: tuple[str, ...]
    has_userinfo: bool
    #: Path and query for the double-encoding check (the authority may
    #: legitimately carry escapes of its own).
    encoded_target: str


def _build_context(
    url: str, policy: SecurityPolicy, parsed: ParsedComponents | None, services: SecurityServices
) -> _CheckContext:
    # NFC-normalizing a pure-ASCII string is always a no-op (Unicode
    # Normalization Form C only recomposes sequences involving combining
    # marks, none of which exist in ASCII), and str.isascii() is a dedicated
    # C-level scan, so this skips the normalize() pass for the common case.
    normalized_url = url if url.isascii() else normalize_url_unicode(url)
    has_authority_syntax = has_scheme_authority(normalized_url)
    split = urlsplit(normalized_url) if has_authority_syntax else None
    encoded_target = f"{split.path}?{split.query}" if split is not None else normalized_url

    if parsed is not None:
        scheme = parsed.scheme
    else:
        try:
            scheme = urlsplit(normalized_url).scheme or None
        except ValueError:
            scheme = None

    raw_host, raw_path = extract_host_and_path(normalized_url)
    canonical_raw_host = _canonical_host(raw_host) if raw_host else ""
    if parsed is not None:
        host = parsed.host or ""
        port = parsed.port
    elif split is not None:
        host = canonical_raw_host
        port = _explicit_port(split)
    else:
        host, port = "", None
    # The raw spelling stays in the set because some findings live only
    # there: IDNA maps a zero-width space to nothing, so it survives in the
    # text a user sees but not in the host the parser stores.
    host_spellings = tuple(dict.fromkeys(h for h in (host, canonical_raw_host, raw_host) if h))
    parsed_path = parsed.path if parsed is not None else None
    return _CheckContext(
        policy=policy,
        services=services,
        url=normalized_url,
        has_authority=has_authority_syntax or bool(parsed is not None and parsed.host),
        scheme=scheme,
        host=host,
        host_spellings=host_spellings,
        port=port,
        path_spellings=tuple(dict.fromkeys(p for p in (raw_path, parsed_path) if p)),
        has_userinfo=has_credentials(normalized_url) or bool(parsed is not None and parsed.userinfo),
        encoded_target=encoded_target,
    )


def _scheme_findings(ctx: _CheckContext) -> list[SecurityFinding]:
    """The policy's scheme rule (see :func:`scheme_rejection`)."""
    if not ctx.scheme:
        return []
    rejection = scheme_rejection(
        ctx.scheme.lower(), allow_custom=ctx.policy.allow_custom_scheme, allowed=ctx.policy.allowed_schemes
    )
    if rejection is None:
        return []
    code, message = rejection
    return [_finding("critical", code, message, "scheme")]


def _encoding_findings(ctx: _CheckContext) -> list[SecurityFinding]:
    if ctx.policy.enforce_double_encoding and has_double_encoding(ctx.encoded_target):
        return [_finding("critical", ErrorCode.DOUBLE_ENCODING, "URL contains double-encoded characters.", "url")]
    return []


def _host_identity_findings(ctx: _CheckContext) -> list[SecurityFinding]:
    """Zone IDs, address rules, SSRF and Unicode host analysis -- on every spelling of the host."""
    policy, spellings = ctx.policy, ctx.host_spellings
    if not spellings:
        return []
    findings: list[SecurityFinding] = []
    if any(is_malicious_ipv6_zone_id(h) for h in spellings):
        findings.append(
            _finding(
                "critical", ErrorCode.INVALID_IPV6_ZONE_ID, "IPv6 zone identifier contains invalid characters.", "host"
            )
        )
    # A denied rule is the caller saying "never this host", so it applies
    # whether or not built-in SSRF enforcement is on.
    if any(policy.host_is_denied(h) for h in spellings):
        findings.append(
            SecurityFinding(
                severity="critical",
                code=ErrorCode.SSRF_RISK.value,
                message="Host matches a denied address rule.",
                component="host",
                remediation="The policy's denied_addresses covers this host.",
            )
        )
    elif policy.enforce_ssrf and any(policy.host_is_ssrf_risk(h) for h in spellings):
        findings.append(_finding("critical", ErrorCode.SSRF_RISK, "Host poses SSRF risk and is disallowed.", "host"))
    # Unicode host analysis. Deliberately NOT gated on the URL being
    # non-ASCII: Punycode is ASCII, and an A-label is exactly how a homograph
    # attack arrives on the wire. analyze_host() decodes first, then works
    # per label.
    enabled_by_code = {
        ErrorCode.MIXED_SCRIPT_LABEL: policy.enforce_mixed_scripts,
        ErrorCode.CONFUSABLE_HOST: policy.enforce_confusable_host,
    }
    reported: set[ErrorCode] = set()
    for spelling in spellings:
        for code, severity, message in analyze_host(spelling):
            if code in reported:
                continue
            reported.add(code)
            if enabled_by_code.get(code, policy.enforce_host_unicode_safety):
                findings.append(_finding(severity, code, message, "host"))
    return findings


def _path_findings(ctx: _CheckContext) -> list[SecurityFinding]:
    """Traversal and open-redirect patterns, in the raw path and the parsed one."""
    findings: list[SecurityFinding] = []
    if ctx.policy.enforce_path_traversal and any(has_path_traversal(p) for p in ctx.path_spellings):
        findings.append(
            _finding("critical", ErrorCode.PATH_TRAVERSAL, "URL path contains path traversal patterns.", "path")
        )
    if ctx.policy.enforce_open_redirect and any(is_open_redirect_risk(p) for p in ctx.path_spellings):
        findings.append(
            _finding("major", ErrorCode.OPEN_REDIRECT, "URL path contains open redirect risk patterns.", "path")
        )
    return findings


def _structure_findings(ctx: _CheckContext) -> list[SecurityFinding]:
    if ctx.policy.enforce_parser_confusion and has_parser_confusion(ctx.url):
        return [
            _finding(
                "critical",
                ErrorCode.PARSER_CONFUSION,
                "URL contains ambiguous syntax that could cause parser confusion.",
                "url",
            )
        ]
    return []


def _credential_findings(ctx: _CheckContext) -> list[SecurityFinding]:
    """Credentials in the authority: advisory unless the policy rejects them.

    They are legal RFC 3986 and common in internal tooling. The phishing
    shape that actually matters ("https://apple.com@evil.com/") is caught
    structurally by enforce_parser_confusion, and .host already resolves to
    the real host either way.
    """
    if not ctx.has_userinfo:
        return []
    if ctx.policy.reject_credentials:
        return [
            _finding("major", ErrorCode.CREDENTIALS_IN_URL, "URL credentials are disallowed by policy.", "userinfo")
        ]
    return [
        _finding(
            "warning",
            ErrorCode.CREDENTIALS_IN_URL,
            "URL contains credentials in the authority. The host resolves to the part "
            "after the last '@'; verify it is the host you expect. Use "
            "URL.redacted() or as_string(mask_password=True) before logging.",
            "userinfo",
        )
    ]


def _port_findings(ctx: _CheckContext) -> list[SecurityFinding]:
    if ctx.policy.block_dangerous_ports and is_commonly_abused_port(ctx.port):
        return [_finding("major", ErrorCode.DANGEROUS_PORT, "URL uses a blocked dangerous port.", "port")]
    return []


def _dns_findings(ctx: _CheckContext) -> list[SecurityFinding]:
    """Resolve the host and check every address under the policy.

    ``host`` is the A-label the caller will connect to. Resolving the raw
    spelling instead let getaddrinfo apply stdlib IDNA 2003, which maps
    "faß.de" to "fass.de" -- a different domain from the "xn--fa-hia.de"
    that URL.host and HTTP clients use.
    """
    policy, host, services = ctx.policy, ctx.host, ctx.services
    if not (policy.check_dns and host):
        return []
    host_allowed_by_name = policy.host_is_allowed(host)
    result = check_host_resolution(
        host,
        policy.dns_options,
        ip_filter=lambda ip: policy.permits_address(ip, host_allowed_by_name=host_allowed_by_name),
        limiter=services.dns_rate_limiter or policy.dns_rate_limiter,
        cache=services.resolution_cache,
        resolver=services.resolver,
        clock=services.clock,
        sleep=services.sleep,
    )
    if result.error is None:
        return []
    return [
        SecurityFinding(
            severity="critical",
            code=result.error.value,
            message=_DNS_MESSAGES.get(result.error, "DNS validation failed."),
            component="host",
            remediation=_REMEDIATION_BY_CODE.get(result.error),
            retry_after=result.retry_after,
        )
    ]


def _phishing_findings(ctx: _CheckContext) -> list[SecurityFinding]:
    policy, host = ctx.policy, ctx.host
    if not (policy.check_phishing and host):
        return []
    listed = ctx.services.feed().lookup(host)
    if listed:
        return [_finding("critical", ErrorCode.PHISHING_DOMAIN, "Host is identified as a phishing domain.", "host")]
    if listed is None:
        # The caller opted into phishing checking and received none. Reporting
        # a clean result would be a lie, so it is surfaced: as a warning (a
        # degraded check, not a detected threat), or as a rejection when the
        # policy says to fail closed.
        return [
            _finding(
                "critical" if policy.phishing_fail_closed else "warning",
                ErrorCode.PHISHING_DB_UNAVAILABLE,
                "Phishing database unavailable; host was not checked.",
                "host",
            )
        ]
    return []


#: The checks, in the order their findings are reported. Order matters:
#: validate_url_security raises on the first blocking finding, so this is
#: also which error a URL with several problems is rejected for.
_CHECKS_WITHOUT_AUTHORITY = (_scheme_findings, _encoding_findings)
_CHECKS_WITH_AUTHORITY = (
    _host_identity_findings,
    _path_findings,
    _structure_findings,
    _credential_findings,
    _port_findings,
    _dns_findings,
    _phishing_findings,
)


def collect_security_findings(
    url: str,
    *,
    policy: PolicyInput = None,
    check_dns: bool | None = None,
    check_phishing: bool | None = None,
    parsed: ParsedComponents | None = None,
    services: SecurityServices | None = None,
) -> list[SecurityFinding]:
    """Collect policy-aware security findings without raising exceptions.

    ``url`` is the raw input. The string heuristics (double encoding, path
    traversal, open redirect, parser confusion, credentials) run on it,
    because the parser normalizes away exactly what they look for.

    ``parsed`` is what the parser produced. When given, its host and port
    are authoritative: DNS, phishing and the dangerous-port check use them
    alone, and the identity checks (SSRF, IPv6 zone ID, Unicode host
    analysis) and the path checks run on them *in addition to* the spelling
    in ``url`` -- a finding on either spelling rejects, so the raw text can
    only add findings, never mask one. Without ``parsed``, the components
    are extracted from ``url`` and canonicalized the way the parser would.

    ``services`` supplies the resolver, caches, limiter and phishing feed
    (default: the process-global ones).
    """
    effective_policy = resolve_security_policy(policy, check_dns=check_dns, check_phishing=check_phishing)
    ctx = _build_context(url, effective_policy, parsed, services if services is not None else DEFAULT_SERVICES)
    checks = _CHECKS_WITHOUT_AUTHORITY + (_CHECKS_WITH_AUTHORITY if ctx.has_authority else ())
    return [finding for check in checks for finding in check(ctx)]


def reject_ambiguous_url(url: str, policy: SecurityPolicy) -> None:
    """Refuse, before parsing, a raw URL that different parsers would read differently.

    Runs ahead of the parser so an ambiguous URL is reported as what it is,
    not as whichever parse error the ambiguity happens to cause. A path the
    traversal or open-redirect checks will report is left to them: theirs
    is the more specific finding.
    """
    if not (policy.enforce_parser_confusion and has_parser_confusion(url)):
        return
    _, path = extract_host_and_path(url)
    if path and (is_open_redirect_risk(path) or has_path_traversal(path)):
        return
    raise InvalidURLError(
        "URL contains ambiguous syntax that could cause parser confusion.",
        code=ErrorCode.PARSER_CONFUSION,
        component="url",
    )


# Severities that represent a detected problem with the URL itself. Anything
# below this is advisory -- it is reported in findings but does not reject the
# URL, because a degraded check is not the same as a failed one.
BLOCKING_SEVERITIES = frozenset({"critical", "major"})

# DNS-specific findings raise their matching DNSRebindingError subclass so a
# caller can distinguish "rate limited" from "resolution failed" from
# "connection check failed" without inspecting .code -- all three remain
# InvalidURLError subclasses, so existing `except InvalidURLError` callers are
# unaffected. Every other finding still raises the generic InvalidURLError.
_EXCEPTION_TYPES_BY_CODE = {
    ErrorCode.UNSUPPORTED_SCHEME: UnsupportedSchemeError,
    ErrorCode.UNSAFE_SCHEME: UnsupportedSchemeError,
    ErrorCode.DNS_RATE_LIMITED: DNSRateLimitError,
    ErrorCode.DNS_RESOLUTION_FAILED: DNSResolutionError,
    ErrorCode.DNS_CONNECTION_FAILED: DNSConnectionError,
}


def validate_url_security(
    url: str,
    *,
    policy: PolicyInput = None,
    check_dns: bool | None = None,
    check_phishing: bool | None = None,
    raise_on_error: bool = True,
    parsed: ParsedComponents | None = None,
    debug: bool = False,
    services: SecurityServices | None = None,
) -> list[SecurityFinding]:
    """Run policy-based security validation, raising on the first blocking finding.

    All findings are returned regardless; only blocking severities raise. This
    lets an advisory finding (for example, "the phishing database could not be
    downloaded, so the host was not checked") reach the caller without turning
    a degraded optional check into a hard parse failure.

    ``parsed`` is passed through to :func:`collect_security_findings`; see
    there for why a parsed URL must supply it. The raised exception's
    ``value`` is the URL with credentials and sensitive parameters redacted,
    unless ``debug=True``.
    """
    findings = collect_security_findings(
        url, policy=policy, check_dns=check_dns, check_phishing=check_phishing, parsed=parsed, services=services
    )
    if raise_on_error:
        for finding in findings:
            if finding.severity in BLOCKING_SEVERITIES:
                code = ErrorCode(finding.code)
                exception_type = _EXCEPTION_TYPES_BY_CODE.get(code, InvalidURLError)
                # Append the remediation so the traceback itself names the way
                # out; the structured field stays available on the finding.
                message = finding.message
                if finding.remediation:
                    message = f"{message} {finding.remediation}"
                value = url if debug else redact_url_for_logs(url)
                if exception_type is DNSRateLimitError:
                    raise DNSRateLimitError(
                        message, component=finding.component, value=value, code=code, retry_after=finding.retry_after
                    )
                raise exception_type(message, component=finding.component, value=value, code=code)
    return findings


def get_cache_info() -> dict:
    """Statistics for the security caches (host classification, Unicode analysis, policies)."""
    return cache_info("security")


def clear_caches() -> dict:
    """Clear the security caches and return their previous sizes."""
    return clear_registered_caches("security")


__all__ = [
    "DEFAULT_SERVICES",
    "DNSCacheConfig",
    "DNSCheckOptions",
    "DNSCheckResult",
    "DNSRateLimiter",
    "DNSRateLimiterConfig",
    "DNSResolutionCache",
    "ParsedComponents",
    "PhishingFeed",
    "PolicyInput",
    "SecurityPolicy",
    "SecurityPolicyError",
    "SecurityServices",
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
    "has_scheme_authority",
    "has_suspicious_punycode",
    "is_commonly_abused_port",
    "is_dangerous_port",
    "is_malicious_ipv6_zone_id",
    "is_open_redirect_risk",
    "is_private_ip",
    "is_ssrf_risk",
    "normalize_url_unicode",
    "redact_component",
    "redact_url_for_logs",
    "refresh_phishing_db",
    "reject_ambiguous_url",
    "reset_dns_rate_limiter",
    "resolve_security_policy",
    "validate_url_security",
]
