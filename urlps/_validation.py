"""Pure URL component validation utilities.

This module provides validation for individual URL components without
any security-related concerns. For security checks, see _security.py.

Naming Convention:
    All validation functions follow the is_valid_*() pattern and return bool.
    They check format compliance (RFC 3986) without security implications.
    Examples: is_valid_host(), is_valid_port(), is_valid_scheme()

Public API:
    - Validator: Class with static methods for validating URL components.
    - is_valid_userinfo: Function to validate userinfo strings.

Performance:
    Frequently-called validators are LRU cached for performance.
    Use Validator.get_cache_info() to monitor cache effectiveness.

All public methods and arguments are type-annotated and documented.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, Optional, TYPE_CHECKING
from functools import lru_cache

from .constants import (
    MAX_HOST_LENGTH,
    MAX_SCHEME_LENGTH,
    MAX_FRAGMENT_LENGTH,
    MAX_IPV6_STRING_LENGTH,
    STANDARD_PORTS,
    MAX_USERINFO_LENGTH,
)
from ._patterns import PATTERNS

if TYPE_CHECKING:
    from types import ModuleType

compiled_regex = PATTERNS

_idna_module: Optional[ModuleType] = None
_HAS_IDNA: bool = False

try:
    import idna as _idna_import  # noqa: F401
    _idna_module = _idna_import
    _HAS_IDNA = True
except ImportError:
    _idna_import = None  # type: ignore[assignment]


class Validator:
    """URL component validation methods.
    
    This class provides pure validation for URL components.
    For security-related checks, use the _security module directly.
    """
    _CACHED_METHODS: list[str] = [
        '_to_ascii_host', 'is_valid_scheme', 'is_valid_host',
        'is_valid_ipv4', 'is_valid_ipv6', 'is_url_safe_string',
        'is_valid_fragment', 'is_ip_address',
    ]

    @staticmethod
    @lru_cache(maxsize=512)
    def _to_ascii_host(host: str) -> str:
        """Return ACE (punycode) form for host.

        Args:
            host: The host string to encode.
        Returns:
            The ASCII-compatible encoding (ACE) of the host.
        """
        if _HAS_IDNA and _idna_module is not None:
            return _idna_module.encode(host).decode("ascii") # type: ignore
        return host.encode("idna").decode("ascii")

    @staticmethod
    @lru_cache(maxsize=512)
    def is_valid_scheme(scheme: str) -> bool:
        """Validate URL scheme.

        Args:
            scheme: The scheme string to validate.
        Returns:
            True if valid, False otherwise.
        """
        if not isinstance(scheme, str) or len(scheme) > MAX_SCHEME_LENGTH:
            return False
        return bool(compiled_regex["scheme"].fullmatch(scheme))

    @staticmethod
    @lru_cache(maxsize=512)
    def is_valid_host(host: str) -> bool:
        """Validate hostname.

        Args:
            host: The host string to validate.
        Returns:
            True if valid, False otherwise.
        """
        if not isinstance(host, str) or len(host) > MAX_HOST_LENGTH:
            return False
        try:
            ascii_host = Validator._to_ascii_host(host)
        except (UnicodeError, UnicodeDecodeError, ValueError):
            return False
        if len(ascii_host) > MAX_HOST_LENGTH:
            return False
        return bool(compiled_regex["host"].fullmatch(ascii_host))

    @staticmethod
    @lru_cache(maxsize=512)
    def is_valid_ipv4(ip: str) -> bool:
        """Validate IPv4 address.

        Args:
            ip: The IPv4 address string.
        Returns:
            True if valid, False otherwise.
        """
        if not isinstance(ip, str) or len(ip) > 15:
            return False
        if not compiled_regex["ipv4"].fullmatch(ip):
            return False
        return Validator._validate_ipv4_octets(ip)

    @staticmethod
    def _validate_ipv4_octets(ip: str) -> bool:
        """Validate IPv4 octets are in valid range without leading zeros.

        Args:
            ip: The IPv4 address string.
        Returns:
            True if all octets are valid, False otherwise.
        """
        octets = ip.split(".")
        if len(octets) != 4:
            return False
        for part in octets:
            if len(part) > 1 and part[0] == '0':
                return False
            try:
                if not 0 <= int(part) <= 255:
                    return False
            except ValueError:
                return False
        return True

    @staticmethod
    @lru_cache(maxsize=512)
    def is_valid_ipv6(ip: str) -> bool:
        """Validate IPv6 address (bracketed format).

        Args:
            ip: The IPv6 address string (must be bracketed).
        Returns:
            True if valid, False otherwise.
        """
        if not isinstance(ip, str) or len(ip) > MAX_IPV6_STRING_LENGTH:
            return False
        if not ip.startswith("[") or not ip.endswith("]"):
            return False
        return Validator._validate_ipv6_inner(ip[1:-1])

    @staticmethod
    def _validate_ipv6_inner(inner: str) -> bool:
        """Validate the inner part of an IPv6 address.

        Args:
            inner: The inner IPv6 address string (no brackets).
        Returns:
            True if valid, False otherwise.
        """
        if "%25" in inner:
            inner, _, _ = inner.partition("%25")
        elif "%" in inner:
            return False
        try:
            ipaddress.IPv6Address(inner)
            return True
        except (ValueError, ipaddress.AddressValueError):
            return False

    @staticmethod
    def is_valid_port(port: Any) -> bool:
        """Validate port number.

        Args:
            port: The port value to validate (int or str).
        Returns:
            True if valid, False otherwise.
        """
        try:
            return 0 < int(port) < 65536
        except (TypeError, ValueError):
            return False

    @staticmethod
    def is_standard_port(port: int) -> bool:
        """Check if port is a standard well-known port.

        Args:
            port: The port number.
        Returns:
            True if standard, False otherwise.
        """
        try:
            return int(port) in STANDARD_PORTS
        except (TypeError, ValueError):
            return False

    @staticmethod
    @lru_cache(maxsize=512)
    def is_url_safe_string(url: str) -> bool:
        """Check if string contains only URL-safe characters (no control characters).

        This is a predicate function that checks character safety without
        performing full validation logic.

        Args:
            url: The string to check.
        Returns:
            True if string contains only URL-safe characters, False otherwise.
        """
        if not isinstance(url, str):
            return False
        return not compiled_regex["control_chars"].search(url)

    @staticmethod
    def is_valid_path(path: str) -> bool:
        """Check if URL path contains only safe characters.

        This delegates to is_url_safe_string() for consistency.

        Args:
            path: The path string.
        Returns:
            True if path contains only safe characters, False otherwise.
        """
        return Validator.is_url_safe_string(path)

    @staticmethod
    def is_valid_query_param(param: str) -> bool:
        """Check if query parameter contains only safe characters.

        This delegates to is_url_safe_string() for consistency.

        Args:
            param: The query parameter string.
        Returns:
            True if parameter contains only safe characters, False otherwise.
        """
        return Validator.is_url_safe_string(param)

    @staticmethod
    @lru_cache(maxsize=512)
    def is_valid_fragment(fragment: str) -> bool:
        """Validate URL fragment.

        Args:
            fragment: The fragment string.
        Returns:
            True if valid, False otherwise.
        """
        if not isinstance(fragment, str) or len(fragment) > MAX_FRAGMENT_LENGTH:
            return False
        return bool(compiled_regex["fragment"].fullmatch(fragment))

    @staticmethod
    @lru_cache(maxsize=512)
    def is_ip_address(host: str) -> bool:
        """Check if host is an IP address literal.

        Args:
            host: The host string.
        Returns:
            True if host is an IP address, False otherwise.
        """
        if not isinstance(host, str):
            return False
        return Validator.is_valid_ipv4(host) or Validator.is_valid_ipv6(host)

    @classmethod
    def get_cache_info(cls) -> Dict[str, Optional[Any]]:
        """Get statistics about validation caches.

        Returns:
            A dictionary mapping method names to cache info dicts.
        """
        stats: Dict[str, Optional[Any]] = {}
        for name in cls._CACHED_METHODS:
            method = getattr(cls, name, None)
            if method and hasattr(method, 'cache_info'):
                info = method.cache_info()
                stats[name] = {
                    'hits': info.hits, 'misses': info.misses,
                    'maxsize': info.maxsize, 'currsize': info.currsize,
                }
            else:
                stats[name] = None
        return stats

    @classmethod
    def clear_caches(cls) -> Dict[str, int]:
        """Clear all validation caches and return previous sizes.

        Returns:
            A dictionary mapping method names to previous cache sizes.
        """
        previous_sizes: Dict[str, int] = {}
        for name in cls._CACHED_METHODS:
            method = getattr(cls, name, None)
            if method and hasattr(method, 'cache_info'):
                previous_sizes[name] = method.cache_info().currsize
                if hasattr(method, 'cache_clear'):
                    method.cache_clear()
            else:
                previous_sizes[name] = 0
        return previous_sizes


def is_valid_userinfo(value: str, max_length: int = MAX_USERINFO_LENGTH) -> bool:
    """Validate userinfo format safely without ReDoS risk.
    
    Args:
        value: The userinfo string to validate.
        max_length: Maximum allowed length.
    Returns:
        True if valid userinfo format, False otherwise.
    """
    if not value or len(value) > max_length or '@' in value:
        return False
    if ':' in value:
        username, _, _ = value.partition(':')
        return bool(username)
    return True


__all__ = ["Validator", "is_valid_userinfo"]
