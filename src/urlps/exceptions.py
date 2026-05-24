"""
Security‑focused exception hierarchy for urlps.

All exceptions inherit from URLpError and provide:
- A human‑readable message
- Optional offending value (safely truncated)
- Optional URL component name
- Optional typed error code
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional, Final


_MAX_VALUE_LENGTH: Final[int] = 200


def _safe_truncated_repr(value: Any, max_length: int = _MAX_VALUE_LENGTH) -> str:
    """Return a truncated repr(value) with strict length limits."""
    try:
        raw = repr(value)
    except Exception:
        return "<unrepresentable>"
    if len(raw) > max_length:
        return raw[: max_length - 3] + "..."
    return raw


class ErrorCode(Enum):
    """Stable error codes for structured downstream handling."""

    SSRF_RISK = "ssrf_risk"
    DNS_RATE_LIMITED = "dns_rate_limited"
    DNS_RESOLUTION_FAILED = "dns_resolution_failed"
    DNS_CONNECTION_FAILED = "dns_connection_failed"
    PHISHING_DOMAIN = "phishing_domain"
    DOUBLE_ENCODING = "double_encoding"
    PATH_TRAVERSAL = "path_traversal"
    OPEN_REDIRECT = "open_redirect"
    MIXED_SCRIPTS = "mixed_scripts"
    PARSER_CONFUSION = "parser_confusion"
    QUERY_INJECTION = "query_injection"
    CREDENTIALS_IN_URL = "credentials_in_url"
    DANGEROUS_PORT = "dangerous_port"
    NON_CANONICAL_URL = "non_canonical_url"
    INVALID_IPV6_ZONE_ID = "invalid_ipv6_zone_id"


class URLpError(Exception):
    """Base class for all urlps exceptions.

    Attributes:
        message: Human‑readable description.
        value: Offending value (optional).
        component: URL component name (optional).
        code: Typed error code (optional).
    """

    __slots__ = ("message", "value", "component", "code")

    def __init__(
        self,
        message: str,
        *,
        value: Any = None,
        component: Optional[str] = None,
        code: Optional[ErrorCode] = None,
    ) -> None:
        super().__init__(message)
        self.message: str = message
        self.value: Any = value
        self.component: Optional[str] = component
        self.code: Optional[ErrorCode] = code

    def __str__(self) -> str:
        base = self.message

        parts = []
        if self.code is not None:
            parts.append(f"code={self.code.value}")
        if self.component is not None:
            parts.append(f"component={self.component!r}")
        if self.value is not None:
            parts.append(f"value={_safe_truncated_repr(self.value)}")

        if parts:
            return f"{base} ({', '.join(parts)})"
        return base


# ---------------------------------------------------------------------------
# Specific Exception Types
# ---------------------------------------------------------------------------

class SecurityPolicyError(URLpError):
    """Raised when an invalid or unsupported security policy is requested."""

class InvalidURLError(URLpError):
    """Raised for invalid URLs or invalid URL components."""

class DNSRateLimiterError(URLpError):
    """Raised when DNS rate limiting encounters an invalid state or input."""

class URLParseError(InvalidURLError):
    """Raised when parsing a URL fails."""


class URLBuildError(InvalidURLError):
    """Raised when constructing a URL from components fails."""


class UnsupportedSchemeError(InvalidURLError):
    """Raised when a scheme is unrecognized or disallowed."""


class RelativeReferenceError(InvalidURLError):
    """Raised when a relative reference is invalid."""


class QuerySerializationError(InvalidURLError):
    """Raised when serializing query parameters fails."""


class QueryParsingError(InvalidURLError):
    """Raised when parsing a query string fails."""


class HostValidationError(InvalidURLError):
    """Raised when a host component is invalid."""


class PortValidationError(InvalidURLError):
    """Raised when a port is missing or invalid."""


class PathNormalizationError(InvalidURLError):
    """Raised when a path cannot be normalized."""


class FragmentEncodingError(InvalidURLError):
    """Raised when a fragment is invalid or cannot be encoded."""


class NetlocBuildingError(InvalidURLError):
    """Raised when constructing userinfo@host:port fails."""


class UserInfoParsingError(InvalidURLError):
    """Raised when userinfo is invalid or cannot be parsed."""


class MissingHostError(InvalidURLError):
    """Raised when a required host is missing."""


class MissingPortError(InvalidURLError):
    """Raised when a required port is missing."""


# ---------------------------------------------------------------------------
# DNS‑related Exceptions
# ---------------------------------------------------------------------------

class DNSRebindingError(InvalidURLError):
    """Base class for DNS rebinding validation failures."""


class DNSRateLimitError(DNSRebindingError):
    """Raised when DNS checks exceed rate limits."""


class DNSResolutionError(DNSRebindingError):
    """Raised when DNS resolution fails."""


class DNSConnectionError(DNSRebindingError):
    """Raised when post‑resolution connection checks fail."""


__all__ = [
    "ErrorCode",
    "URLpError",
    "InvalidURLError",
    "URLParseError",
    "URLBuildError",
    "UnsupportedSchemeError",
    "RelativeReferenceError",
    "QuerySerializationError",
    "QueryParsingError",
    "HostValidationError",
    "PortValidationError",
    "PathNormalizationError",
    "FragmentEncodingError",
    "NetlocBuildingError",
    "UserInfoParsingError",
    "MissingHostError",
    "MissingPortError",
    "DNSRebindingError",
    "DNSRateLimitError",
    "DNSResolutionError",
    "DNSConnectionError",
    "SecurityPolicyError"
]
