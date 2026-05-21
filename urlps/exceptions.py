"""
Exception hierarchy for urlps: all errors raised by urlps are subclasses of URLpError.

Each exception provides a message, the value that caused the error (if applicable),
and the URL component involved (if applicable). This enables precise error handling
and better diagnostics for users and tools.
"""

from enum import Enum
from typing import Any, Optional

# Maximum length for value representation in error messages
_MAX_VALUE_LENGTH = 200


def _truncate_value(value: Any, max_length: int = _MAX_VALUE_LENGTH) -> str:
    """Truncate a value's repr if it exceeds max_length."""
    value_repr = repr(value)
    if len(value_repr) > max_length:
        return value_repr[:max_length - 3] + "..."
    return value_repr


class URLpError(Exception):
    """Base exception for URLp errors.

    Args:
        message: Human-readable error message.
        value: The value that caused the error (optional).
        component: The URL component involved (optional).
    Attributes:
        message (str): The error message.
        value (Any): The value that caused the error, if available.
        component (Optional[str]): The URL component involved, if available.
    """
    def __init__(
        self,
        message: str = "",
        value: Any = None,
        component: Optional[str] = None,
        code: Optional["ErrorCode"] = None,
    ) -> None:
        super().__init__(message)
        self.value: Any = value
        self.component: Optional[str] = component
        self.message: str = message
        self.code: Optional[ErrorCode] = code

    def __str__(self) -> str:
        base = super().__str__()
        if self.value is not None or self.component:
            truncated_value = _truncate_value(self.value)
            if self.code is not None:
                return f"{base} (code={self.code.value}, component={self.component!r}, value={truncated_value})"
            return f"{base} (component={self.component!r}, value={truncated_value})"
        if self.code is not None:
            return f"{base} (code={self.code.value})"
        return base


class ErrorCode(Enum):
    """Typed error codes for stable downstream error handling."""

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

class InvalidURLError(URLpError):
    """Exception raised for invalid URLs or components.

    Args:
        message: Error message.
        value: The invalid value.
        component: The URL component (e.g., 'host', 'port').
    """
    pass

class URLParseError(InvalidURLError):
    """Exception raised for errors during URL parsing.

    Raised when a URL string cannot be parsed or fails validation.
    """
    pass

class URLBuildError(InvalidURLError):
    """Exception raised for errors during URL building.

    Raised when constructing a URL from components fails validation.
    """
    pass

class UnsupportedSchemeError(InvalidURLError):
    """Exception raised for unsupported URL schemes.

    Raised when a scheme is not recognized or not allowed by the parser.
    """
    pass

class RelativeReferenceError(InvalidURLError):
    """Exception raised for errors in relative URL references.

    Raised when parsing or building a relative reference fails.
    """
    pass

class QuerySerializationError(InvalidURLError):
    """Exception raised for errors during query serialization.

    Raised when serializing query parameters fails.
    """
    pass

class QueryParsingError(InvalidURLError):
    """Exception raised for errors during query parsing.

    Raised when parsing a query string fails or is invalid.
    """
    pass

class HostValidationError(InvalidURLError):
    """Exception raised for invalid hostnames.

    Raised when a host component is invalid or fails validation.
    """
    pass

class PortValidationError(InvalidURLError):
    """Exception raised for invalid port numbers.

    Raised when a port is missing, out of range, or not numeric.
    """
    pass

class PathNormalizationError(InvalidURLError):
    """Exception raised for errors during path normalization.

    Raised when a path cannot be normalized or is invalid.
    """
    pass

class FragmentEncodingError(InvalidURLError):
    """Exception raised for errors during fragment encoding.

    Raised when a fragment is invalid or cannot be encoded.
    """
    pass

class NetlocBuildingError(InvalidURLError):
    """Exception raised for errors during netloc building.

    Raised when constructing the netloc (userinfo@host:port) fails.
    """
    pass

class UserInfoParsingError(InvalidURLError):
    """Exception raised for errors during userinfo parsing.

    Raised when the userinfo component is invalid or cannot be parsed.
    """
    pass

class MissingHostError(InvalidURLError):
    """Exception raised when a required host is missing.

    Raised when a host is required but not provided.
    """
    pass

class MissingPortError(InvalidURLError):
    """Exception raised when a required port is missing.

    Raised when a port is required but not provided.
    """
    pass


class DNSRebindingError(InvalidURLError):
    """Base exception for DNS rebinding validation failures."""


class DNSRateLimitError(DNSRebindingError):
    """Raised when DNS checks are blocked by rate limiting."""


class DNSResolutionError(DNSRebindingError):
    """Raised when DNS resolution fails."""


class DNSConnectionError(DNSRebindingError):
    """Raised when post-resolution connection safety verification fails."""


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
]
