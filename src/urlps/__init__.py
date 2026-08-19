"""urlps - Lightweight, secure, and RFC-compliant URL parsing and building.

Quick Start:
    >>> from urlps import parse_url, build
    >>> url = parse_url("https://example.com/path?query=value")
    >>> url.host
    'example.com'
    >>> build("https", "example.com", path="/api", query="v=1")
    'https://example.com/api?v=1'

Main Entry Points:
    parse_url(url, **options) -> URL
        Parsing with security checks, governed by a policy (default:
        "strict"). Enabled under both "strict" and "balanced":
        - SSRF protection (private IPs, localhost, cloud metadata endpoints)
        - Path traversal detection (.., null bytes, encoded variants)
        - Open redirect detection (backslashes, leading //)
        - Homograph detection (mixed scripts and whole-script confusables,
          evaluated per label on the Punycode-decoded host)
        - Parser confusion detection (ambiguous URL structures)
        - Double-encoding detection

        Cosmetic differences are normalized rather than rejected: host case,
        a trailing root dot, default ports, dot segments and percent-encoding
        spelling all resolve to one canonical form, so `url.host` is directly
        comparable against an allowlist.

        Use this for URLs from untrusted sources (user input, external APIs).

    join(base, reference, **options) -> URL
        RFC 3986 Section 5 reference resolution. The security-preserving
        equivalent of urllib.parse.urljoin -- the resolved target is
        validated, so resolution cannot bypass the checks above.

    parse_url_local(url, **options) -> URL
        Development and internal URLs: the heuristic checks are off and
        loopback/RFC1918 hosts are permitted, so "http://localhost:3000"
        parses. SSRF enforcement is narrowed, NOT disabled -- cloud metadata
        endpoints, the link-local range, .internal and kubernetes service
        names stay blocked.

        WARNING: Never use with user input or external data.
        (parse_url_unsafe is the former name and still works.)

    build(scheme_and_host, **components) -> str
        Construct URLs from components with proper encoding.
        Components: port, path, query, fragment, userinfo
        Examples:
            build("example.com")  # Scheme-less URL
            build("https", "example.com", port=8443)

    compose_url(components: dict) -> str
        Build URL from dictionary of components.
        Useful when working with structured data.

    URL
        Immutable URL object with rich manipulation API.
        Created by parse_url() or parse_url_local().
        Methods: with_host(), with_port(), with_query_param(), etc.

Performance:
    - get_cache_info(): View cache statistics for optimization
    - clear_all_caches(): Clear internal caches (useful for long-running apps)
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__version__ = "1.0.1"

from . import _parser
from . import url as _url
from ._audit import AuditCallback, AuditConfig, AuditEventCallback, AuditManager
from ._components import SecurityFinding
from ._security.dns_guard import DNSRateLimiter, DNSRateLimiterConfig
from ._security.policy import PolicyInput, SecurityPolicy, resolve_security_policy
from .exceptions import (
    DNSConnectionError,
    DNSRateLimiterError,
    DNSRateLimitError,
    DNSRebindingError,
    DNSResolutionError,
    ErrorCode,
    FragmentEncodingError,
    HostValidationError,
    InvalidURLError,
    MissingHostError,
    PhishingDatabaseError,
    PortValidationError,
    QueryParsingError,
    RelativeReferenceError,
    SecurityPolicyError,
    UnsupportedSchemeError,
    URLBuildError,
    URLParseError,
    URLpError,
    UserInfoParsingError,
)
from .url import URL


def parse_url(
    url: str,
    *,
    allow_custom_scheme: bool = False,
    check_dns: bool = False,
    check_phishing: bool = False,
    dns_rate_limiter: DNSRateLimiter | None = None,
    policy: PolicyInput = None,
    correlation_id: str | None = None,
    audit: AuditConfig | None = None,
) -> URL:
    """Parse a URL with security checks applied (recommended entry point).

    Use this for URLs from untrusted sources. Which checks run is determined
    entirely by the security policy; the default is ``strict``.

    Cosmetic differences are *normalized*, not rejected. ``HTTP://EXAMPLE.COM./``,
    ``https://example.com:443/``, ``/a/./b`` and ``%7E`` all parse fine and
    resolve to one canonical form, so ``url.host`` can be compared against an
    allowlist directly. Rejection is reserved for input that is genuinely
    malformed or genuinely dangerous.

    Enabled under both ``strict`` and ``balanced``:
        - SSRF protection: private IPs (10.x, 192.168.x, 172.16-31.x),
          localhost, ::1, *.local, and cloud metadata endpoints
          (169.254.169.254, metadata.google.internal)
        - Path traversal detection: ``../``, null bytes, encoded variants
        - Double-encoding detection: ``%25`` patterns used to bypass filters
        - Open redirect detection: backslashes, leading ``//`` (raw or
          percent-encoded)
        - Homograph detection: mixed scripts *and* whole-script confusables,
          evaluated per label on the Punycode-decoded host, so
          ``xn--pypal-4ve.com`` (Cyrillic а) is caught while ``例え.com`` and
          ``münchen.de`` are not
        - Parser confusion: ambiguous URLs parsed differently across parsers
        - Bidi controls, zero-width characters and malformed Punycode in the host

    Off by default, opt in via SecurityPolicy:
        - ``block_dangerous_ports``: SSRF already covers the internal-service
          case, and blocking port 22 on a public host prevents nothing
        - ``reject_credentials``: ``user:pass@host`` is legal RFC 3986; a
          non-blocking advisory finding is emitted either way

    Optional, off by default under every policy:
        - DNS rebinding (``check_dns=True``): verifies the host resolves to a
          safe IP. Performs blocking network I/O; see the README.
        - Phishing domains (``check_phishing=True``): checks a downloaded
          database. Performs blocking network I/O on first use.

    Args:
        url: The URL string to parse
        allow_custom_scheme: If True, allow non-standard schemes (default: False)
            Standard schemes: http, https, ftp, ftps, sftp, file, ws, wss
        check_dns: If True, perform DNS lookup to verify host resolves to safe IP.
            WARNING: Has performance impact and is rate-limited to prevent DoS.
            Use only when DNS rebinding is a concern (default: False)
        check_phishing: If True, check hostname against known phishing database.
            Downloads database on first use. Best for user-facing applications
            where phishing is a concern (default: False)
        dns_rate_limiter: Optional DNSRateLimiter instance to enforce DNS lookup
            rate limits with dependency injection (recommended for isolation).
            If omitted, DNS checks use the process-global compatibility limiter.
        policy: Security policy -- "strict", "balanced", "internal", "local",
            or a SecurityPolicy instance. This is the single control for
            which checks are enforced.
        correlation_id: Optional identifier propagated to audit events.
        audit: Optional AuditConfig supplying audit callbacks for this parse.

    Returns:
        URL: Immutable URL object with all parsed components

    Raises:
        InvalidURLError: If URL fails security validation
        URLParseError: If URL structure is invalid

    Examples:
        >>> url = parse_url("https://api.example.com/users?id=123")
        >>> url.host
        'api.example.com'

        >>> parse_url("http://localhost/admin")  # Raises InvalidURLError
        >>> parse_url("http://192.168.1.1/")     # Raises InvalidURLError

    For internal/development URLs, use parse_url_local() instead.
    """
    resolved_policy = resolve_security_policy(
        policy,
        check_dns=check_dns,
        check_phishing=check_phishing,
        dns_rate_limiter=dns_rate_limiter,
    )
    parser = _parser.Parser()
    parser.custom_scheme = allow_custom_scheme
    return _url.URL(
        url,
        parser=parser,
        check_dns=resolved_policy.check_dns,
        check_phishing=resolved_policy.check_phishing,
        security_policy=resolved_policy,
        correlation_id=correlation_id,
        audit=audit,
    )


def parse_url_unsafe(
    url: str,
    *,
    allow_custom_scheme: bool = False,
    debug: bool = False,
    check_dns: bool = False,
    dns_rate_limiter: DNSRateLimiter | None = None,
    policy: PolicyInput = None,
    correlation_id: str | None = None,
    audit: AuditConfig | None = None,
) -> URL:
    """Parse a local/development URL, with the heuristic checks turned off.

    Deprecated alias for :func:`parse_url_local`, which says what this actually
    does. Use that instead; this name is retained for compatibility.

    Applies the ``local`` policy: the heuristic checks (path traversal, open
    redirect, parser confusion, mixed scripts, double encoding, Punycode) are
    off, and loopback/RFC1918 hosts are permitted so ``http://localhost:3000``
    parses. SSRF enforcement is *narrowed, not disabled* -- cloud metadata
    endpoints (169.254.169.254, metadata.google.internal), the whole link-local
    range, ``.internal`` and kubernetes service names remain blocked.

    Use ONLY for:
        - Internal URLs (localhost, 192.168.x.x, 10.x.x.x)
        - Development/testing environments
        - Configuration files from trusted sources
        - URLs already validated by upstream security layers

    NEVER use this function with:
        - User-provided input
        - URLs from external APIs
        - Data from untrusted sources
        - URLs forwarded to other services

    Args:
        url: The URL string to parse
        allow_custom_scheme: If True, allow non-standard URL schemes (default: False)
        debug: If True, include raw input in error traces for debugging (default: False)
        check_dns: If True, verify hostname resolution and block private/reserved targets.
            Useful for DNS rebinding protection in internal environments (default: False)
            Ignored when an explicit policy is provided.
        dns_rate_limiter: Optional DNSRateLimiter instance to use when DNS checks
            are enabled. Prefer explicit injection for deterministic behavior.
        policy: Optional policy to apply instead of the default ``local``
            preset. To re-enable protections, pass ``policy="strict"`` or use
            ``parse_url()`` rather than reaching for a separate flag.
        correlation_id: Optional identifier propagated to audit events.
        audit: Optional AuditConfig supplying audit callbacks for this parse.

    Returns:
        URL: Immutable URL object with all parsed components

    Raises:
        URLParseError: If URL structure is invalid (format errors only, not security)

    Examples:
        >>> url = parse_url_unsafe("http://localhost:3000/api")
        >>> url.port
        3000

        >>> url = parse_url_unsafe("http://192.168.1.100/metrics")
        >>> url.host
        '192.168.1.100'

    Security Note:
        For production use with untrusted input, always use parse_url() instead.
    """
    resolved_policy = (
        resolve_security_policy(policy, dns_rate_limiter=dns_rate_limiter)
        if policy is not None
        else SecurityPolicy.local(
            check_dns=check_dns,
            dns_rate_limiter=dns_rate_limiter,
        )
    )

    parser = _parser.Parser()
    parser.custom_scheme = allow_custom_scheme
    return _url.URL(
        url,
        parser=parser,
        debug=debug,
        check_dns=resolved_policy.check_dns,
        check_phishing=resolved_policy.check_phishing,
        security_policy=resolved_policy,
        correlation_id=correlation_id,
        audit=audit,
    )


#: Alias for :func:`parse_url_unsafe`. Under the ``local`` policy, cloud
#: metadata endpoints and the link-local range still stay blocked.
parse_url_local = parse_url_unsafe


def build(
    *scheme_and_host: str,
    port: int | None = None,
    path: str = "/",
    query: str | None = None,
    fragment: str | None = None,
    userinfo: str | None = None,
) -> str:
    """Build a URL string from individual components with automatic encoding.

    This function constructs a properly-formatted and encoded URL from its parts.
    Components are automatically percent-encoded as needed per RFC 3986.

    Args:
        scheme_and_host: Flexible positional arguments for scheme and host:
            - One argument: Treated as host only (scheme-less URL)
              Example: build("example.com") -> "example.com/"
            - Two arguments: First is scheme, second is host
              Example: build("https", "example.com") -> "https://example.com/"
            - Three+ arguments: Extra arguments are ignored
        port: Port number (1-65535). Default ports (80 for http, 443 for https)
            are automatically omitted from the output (default: None)
        path: URL path component. Automatically normalized (resolves .. and .)
            and percent-encoded. Leading / is added if missing when host is present
            (default: "/")
        query: Query string without leading '?'. Raw string or use compose_url()
            with query_pairs for automatic encoding (default: None)
        fragment: Fragment identifier without leading '#'. Automatically
            percent-encoded (default: None)
        userinfo: User authentication info in 'user:password' format.
            WARNING: Including passwords in URLs is deprecated and insecure
            (default: None)

    Returns:
        str: The fully-composed URL string

    Raises:
        URLBuildError: If host is required but not provided, or if components are invalid

    Examples:
        >>> build("example.com")
        'example.com/'

        >>> build("https", "example.com", port=443, path="/api")
        'https://example.com/api'  # Port 443 omitted (default for https)

        >>> build("https", "api.example.com", path="/users", query="limit=10", fragment="results")
        'https://api.example.com/users?limit=10#results'

        >>> build("http", "admin:secret@example.com", port=8080)
        'http://admin:secret@example.com:8080/'

    Note:
        For building URLs from dictionaries or with query parameter lists,
        see compose_url() which provides a dict-based interface.
    """
    from . import _builder as _builder

    if len(scheme_and_host) == 1:
        scheme = None
        host = scheme_and_host[0]
    elif len(scheme_and_host) >= 2:
        scheme, host, *_ = scheme_and_host
    else:
        from .exceptions import URLBuildError

        raise URLBuildError("At least host must be provided to build a URL.")

    return _builder.Builder().compose(
        {
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
            "query": query,
            "fragment": fragment,
            "userinfo": userinfo,
        }
    )


def join(
    base: str | URL,
    reference: str | URL,
    *,
    allow_custom_scheme: bool = False,
    check_dns: bool = False,
    check_phishing: bool = False,
    dns_rate_limiter: DNSRateLimiter | None = None,
    policy: PolicyInput = None,
    correlation_id: str | None = None,
    audit: AuditConfig | None = None,
    strict_resolution: bool = True,
) -> URL:
    """Resolve a URI reference against a base URI (RFC 3986 Section 5).

    This is the security-preserving equivalent of ``urllib.parse.urljoin``.
    The resolved target is parsed and validated under a security policy, so
    resolution cannot be used to escape the checks that ``parse_url`` applies.
    That matters because reference resolution is exactly where an attacker
    controls part of the input:

        >>> join("https://example.com/a/b", "../c")
        URL('https://example.com/c')
        >>> join("https://example.com/a/", "//evil.example/x")  # authority swap
        URL('https://evil.example/x')

    The second example shows why validating the *result* is the whole point: a
    protocol-relative reference legitimately replaces the host, so the target
    must be re-checked rather than trusted because the base was trusted.

    Dot segments cannot escape the root -- excess ``..`` segments are
    discarded per RFC 3986 Section 5.2.4 -- so ``join(base, "../../../../etc")``
    stays within the base authority.

    Args:
        base: The base URI. Must be absolute (have a scheme).
        reference: The reference to resolve. May be absolute, protocol-relative,
            absolute-path, relative-path, query-only, or fragment-only.
        allow_custom_scheme: Allow non-standard schemes in the result.
        check_dns: Verify the resolved host resolves to a safe IP.
        check_phishing: Check the resolved host against the phishing database.
        dns_rate_limiter: Optional DNSRateLimiter for DNS check isolation.
        policy: Security policy applied to the resolved target.
        correlation_id: Optional identifier propagated to audit events.
        audit: Optional AuditConfig supplying audit callbacks.
        strict_resolution: When False, apply the RFC 3986 Section 5.2.2
            backwards-compatibility rule that treats a reference whose scheme
            matches the base scheme as scheme-less. Defaults to True.

    Returns:
        URL: The validated, resolved target.

    Raises:
        ValueError: If ``base`` is not absolute.
        InvalidURLError: If the resolved target fails security validation.
        URLParseError: If the resolved target is structurally invalid.
    """
    from ._resolve import resolve_reference

    base_str = base.as_string() if isinstance(base, URL) else base
    reference_str = reference.as_string() if isinstance(reference, URL) else reference

    if not isinstance(base_str, str):
        raise TypeError(f"base must be str or URL, got {type(base).__name__}")
    if not isinstance(reference_str, str):
        raise TypeError(f"reference must be str or URL, got {type(reference).__name__}")

    target = resolve_reference(base_str, reference_str, strict=strict_resolution)

    return parse_url(
        target,
        allow_custom_scheme=allow_custom_scheme,
        check_dns=check_dns,
        check_phishing=check_phishing,
        dns_rate_limiter=dns_rate_limiter,
        policy=policy,
        correlation_id=correlation_id,
        audit=audit,
    )


def compose_url(components: Mapping[str, Any]) -> str:
    """Compose a URL from components dict.

    Args:
        components: Dict with keys: scheme, host, port, path, query, fragment, userinfo

    Returns:
        The composed URL string.
    """
    from . import _builder as _builder

    return _builder.Builder().compose(components)


def build_secure(
    *scheme_and_host: str,
    policy: PolicyInput = None,
    check_dns: bool = False,
    check_phishing: bool = False,
    dns_rate_limiter: DNSRateLimiter | None = None,
    correlation_id: str | None = None,
    audit: AuditConfig | None = None,
    port: int | None = None,
    path: str = "/",
    query: str | None = None,
    fragment: str | None = None,
    userinfo: str | None = None,
) -> str:
    """Build then validate a URL under a security policy, raising on policy violations.

    Args:
        dns_rate_limiter: Optional DNSRateLimiter instance used when DNS checks
            are enabled by flags or policy.
        audit: Optional AuditConfig supplying audit callbacks for the
            validation parse.
    """
    composed = build(
        *scheme_and_host,
        port=port,
        path=path,
        query=query,
        fragment=fragment,
        userinfo=userinfo,
    )
    parsed = parse_url(
        composed,
        check_dns=check_dns,
        check_phishing=check_phishing,
        dns_rate_limiter=dns_rate_limiter,
        policy=policy,
        correlation_id=correlation_id,
        audit=audit,
    )
    return parsed.as_string()


def get_cache_info() -> dict:
    """Get statistics about all internal caches.

    Returns a dictionary with cache statistics for performance-critical functions:
    - Parser caches (path normalization)
    - Validation caches (scheme, host, IP validation)
    - Security caches (SSRF detection, mixed scripts)
    - Builder caches (percent encoding, query encoding)

    Returns:
        Dictionary mapping module names to their cache statistics.

    Example:
        >>> info = get_cache_info()
        >>> info['parser']['normalize_path']['hits']
        450
    """
    from . import _builder, _parser, _security, _validation

    return {
        "parser": _parser.get_cache_info(),
        "validation": _validation.Validator.get_cache_info(),
        "security": _security.get_cache_info(),
        "builder": {
            "percent_encode": _builder.Builder._percent_encode_cached.cache_info()._asdict()
            if hasattr(_builder.Builder._percent_encode_cached, "cache_info")
            else None,
            "encode_for_query": _builder._encode_for_query.cache_info()._asdict()
            if hasattr(_builder._encode_for_query, "cache_info")
            else None,
        },
    }


def clear_all_caches() -> dict:
    """Clear all internal caches and return previous sizes.

    This can be useful for:
    - Memory management in long-running applications
    - Testing to ensure fresh state
    - Resetting after processing a large batch of URLs

    Returns:
        Dictionary mapping module names to previous cache sizes.

    Example:
        >>> previous = clear_all_caches()
        >>> previous['parser']['normalize_path']
        127
    """
    from . import _builder, _parser, _security, _validation

    previous = {
        "parser": _parser.clear_caches(),
        "validation": _validation.Validator.clear_caches(),
        "security": _security.clear_caches(),
        "builder": {},
    }

    if hasattr(_builder.Builder._percent_encode_cached, "cache_clear"):
        previous["builder"]["percent_encode"] = _builder.Builder._percent_encode_cached.cache_info().currsize
        _builder.Builder._percent_encode_cached.cache_clear()

    if hasattr(_builder._encode_for_query, "cache_clear"):
        previous["builder"]["encode_for_query"] = _builder._encode_for_query.cache_info().currsize
        _builder._encode_for_query.cache_clear()

    return previous


__all__ = [
    "URL",
    "AuditCallback",
    "AuditConfig",
    "AuditEventCallback",
    "AuditManager",
    "DNSConnectionError",
    "DNSRateLimitError",
    "DNSRateLimiter",
    "DNSRateLimiterConfig",
    "DNSRateLimiterError",
    "DNSRebindingError",
    "DNSResolutionError",
    "ErrorCode",
    "FragmentEncodingError",
    "HostValidationError",
    "InvalidURLError",
    "MissingHostError",
    "PhishingDatabaseError",
    "PolicyInput",
    "PortValidationError",
    "QueryParsingError",
    "RelativeReferenceError",
    "SecurityFinding",
    "SecurityPolicy",
    "SecurityPolicyError",
    "URLBuildError",
    "URLParseError",
    "URLpError",
    "UnsupportedSchemeError",
    "UserInfoParsingError",
    "__version__",
    "build",
    "build_secure",
    "clear_all_caches",
    "compose_url",
    "get_cache_info",
    "join",
    "parse_url",
    "parse_url_local",
    "parse_url_unsafe",
]
