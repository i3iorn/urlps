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
        (parse_url_unsafe is a deprecated alias for this function; it still
        works but emits a DeprecationWarning and will be removed in a future
        major release.)

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

__version__ = "1.1.0"

from ._audit import AuditCallback, AuditConfig, AuditEventCallback, AuditManager
from ._components import SecurityFinding
from ._diagnostics import clear_all_caches, get_cache_info
from ._entrypoints import (
    build,
    build_secure,
    compose_url,
    join,
    parse_url,
    parse_url_local,
    parse_url_unsafe,
)
from ._security.dns_guard import DNSRateLimiter, DNSRateLimiterConfig
from ._security.policy import PolicyInput, SecurityPolicy
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
