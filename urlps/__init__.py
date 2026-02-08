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
        Secure-by-default parsing with comprehensive security checks:
        - SSRF protection (blocks private IPs, localhost, metadata endpoints)
        - Path traversal detection (.., null bytes, encoded variants)
        - Homograph attack detection (mixed Unicode scripts)
        - Parser confusion detection (ambiguous URL structures)
        - Double-encoding detection

        Use this for parsing URLs from untrusted sources (user input, external APIs).

    parse_url_unsafe(url, **options) -> URL
        Parsing WITHOUT security validations. Use ONLY for:
        - Internal/development URLs (localhost, 192.168.x.x)
        - Trusted configuration files
        - URLs from verified sources

        WARNING: Never use with user input or external data.

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
        Created by parse_url() or parse_url_unsafe().
        Methods: with_host(), with_port(), with_query_param(), etc.

Performance:
    - get_cache_info(): View cache statistics for optimization
    - clear_all_caches(): Clear internal caches (useful for long-running apps)
"""
from __future__ import annotations

from typing import Any, Mapping, Optional
import importlib

__version__ = "0.4.0"

from urlps._audit import set_audit_callback, get_audit_callback
from urlps.exceptions import URLpError, InvalidURLError, URLParseError, URLBuildError
from urlps.url import URL



def parse_url(
    url: str, *,
    allow_custom_scheme: bool = False,
    check_dns: bool = False,
    check_phishing: bool = False
) -> "URL":
    """Parse URL with comprehensive security checks enabled (SECURE BY DEFAULT).

    This is the recommended function for parsing URLs from untrusted sources.
    It provides defense-in-depth against common URL-based attacks.

    Security Features (Always Enabled):
        - SSRF protection: Blocks private IPs (10.x, 192.168.x, 172.16-31.x)
        - Localhost blocking: Rejects localhost, 127.0.0.1, ::1, *.local domains
        - Cloud metadata blocking: Prevents access to 169.254.169.254, metadata.google.internal
        - Path traversal detection: Identifies ../, null bytes, encoded variants
        - Double-encoding detection: Catches %25 patterns used to bypass filters
        - Open redirect detection: Blocks URLs with backslashes, leading //
        - Homograph attacks: Detects mixed Unicode scripts (e.g., Cyrillic 'а' vs Latin 'a')
        - Parser confusion: Identifies ambiguous URLs parsed differently across parsers

    Optional Security Checks:
        - DNS rebinding (check_dns=True): Verifies hostname resolves to safe IPs
        - Phishing domains (check_phishing=True): Checks against known phishing database

    Args:
        url: The URL string to parse
        allow_custom_scheme: If True, allow non-standard schemes (default: False)
            Standard schemes: http, https, ftp, ftps, sftp, file, ws, wss
        check_dns: If True, perform DNS lookup to verify host resolves to safe IP.
            WARNING: Has performance impact and is rate-limited to prevent DoS.
            Use only when DNS rebinding is a concern (default: False)
        check_phishing: If True, check hostname against known phishing database.
            Downloads database on first use (~10MB). Best for user-facing applications
            where phishing is a concern (default: False)

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

    For internal/development URLs, use parse_url_unsafe() instead.
    """
    from . import _security as _security
    from . import _parser as _parser
    from . import url as _url

    _security.validate_url_security(url)
    parser = _parser.Parser()
    parser.custom_scheme = allow_custom_scheme
    return _url.URL(url, parser=parser, strict=True, check_dns=check_dns, check_phishing=check_phishing)


def parse_url_unsafe(
    url: str, *,
    allow_custom_scheme: bool = False,
    strict: bool = False,
    debug: bool = False,
    check_dns: bool = False
) -> "URL":
    """Parse a URL string WITHOUT security checks (for trusted sources only).

    WARNING: This function DISABLES security validations. Use ONLY for:
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
        strict: If True, enable SSRF checks (negates "unsafe" mode). Rarely needed.
            Use parse_url() instead if you need security (default: False)
        debug: If True, include raw input in error traces for debugging (default: False)
        check_dns: If True, verify hostname resolves (but doesn't check if IP is safe).
            Mainly useful for detecting typos in internal hostnames (default: False)

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
    from . import _parser as _parser
    from . import url as _url

    parser = _parser.Parser()
    parser.custom_scheme = allow_custom_scheme
    return _url.URL(url, parser=parser, strict=strict, debug=debug, check_dns=check_dns)



def build(
    *scheme_and_host: str,
    port: Optional[int] = None,
    path: str = "/",
    query: Optional[str] = None,
    fragment: Optional[str] = None,
    userinfo: Optional[str] = None,
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

    return _builder.Builder().compose({
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "query": query,
        "fragment": fragment,
        "userinfo": userinfo,
    })


def compose_url(components: Mapping[str, Any]) -> str:
    """Compose a URL from components dict.

    Args:
        components: Dict with keys: scheme, host, port, path, query, fragment, userinfo

    Returns:
        The composed URL string.
    """
    from . import _builder as _builder
    return _builder.Builder().compose(components)



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
    from . import _parser, _validation, _security, _builder

    return {
        'parser': _parser.get_cache_info(),
        'validation': _validation.Validator.get_cache_info(),
        'security': _security.get_cache_info(),
        'builder': {
            'percent_encode': _builder.Builder._percent_encode_cached.cache_info()._asdict()
                if hasattr(_builder.Builder._percent_encode_cached, 'cache_info') else None,
            'encode_for_query': _builder._encode_for_query.cache_info()._asdict()
                if hasattr(_builder._encode_for_query, 'cache_info') else None,
        }
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
    from . import _parser, _validation, _security, _builder

    previous = {
        'parser': _parser.clear_caches(),
        'validation': _validation.Validator.clear_caches(),
        'security': _security.clear_caches(),
        'builder': {}
    }

    if hasattr(_builder.Builder._percent_encode_cached, 'cache_clear'):
        previous['builder']['percent_encode'] = _builder.Builder._percent_encode_cached.cache_info().currsize
        _builder.Builder._percent_encode_cached.cache_clear()

    if hasattr(_builder._encode_for_query, 'cache_clear'):
        previous['builder']['encode_for_query'] = _builder._encode_for_query.cache_info().currsize
        _builder._encode_for_query.cache_clear()

    return previous


__all__ = [
    "__version__",
    "parse_url",
    "parse_url_unsafe",
    "build",
    "compose_url",
    "URL",
    "URLpError",
    "InvalidURLError",
    "URLParseError",
    "URLBuildError",
    "set_audit_callback",
    "get_audit_callback",
    "get_cache_info",
    "clear_all_caches",
]
