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
    Frequently-called validators are LRU cached; urlps.get_cache_info()
    reports them under "validation".

All public methods and arguments are type-annotated and documented.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Set as AbstractSet
from typing import Any
from urllib.parse import unquote

from ._cache_config import VALIDATION_CACHE_SIZE, bounded_lru_cache, cache_info, lru_cache
from ._cache_config import clear_caches as clear_registered_caches
from ._host import port_number
from ._patterns import PATTERNS
from ._security._unicode.uts46 import to_ascii
from .constants import (
    MAX_FRAGMENT_LENGTH,
    MAX_HOST_LENGTH,
    MAX_IPV6_STRING_LENGTH,
    MAX_SCHEME_LENGTH,
    MAX_USERINFO_LENGTH,
    STANDARD_SCHEMES,
    UNSAFE_SCHEMES,
)
from .exceptions import ErrorCode, InvalidURLError

compiled_regex = PATTERNS


class Validator:
    """URL component validation methods.

    This class provides pure validation for URL components.
    For security-related checks, use the _security module directly.
    """

    @staticmethod
    @lru_cache(maxsize=VALIDATION_CACHE_SIZE, group="validation")
    def _to_ascii_host(host: str) -> str:
        """Return ACE (punycode) form for host.

        Args:
            host: The host string to encode.
        Returns:
            The ASCII-compatible encoding (ACE) of the host.
        """
        # Delegates: a second IDNA implementation here is exactly how the
        # parser and the validator came to disagree about "straße.de".
        return to_ascii(host)

    @staticmethod
    @bounded_lru_cache(maxsize=VALIDATION_CACHE_SIZE, group="validation")
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
    @bounded_lru_cache(maxsize=VALIDATION_CACHE_SIZE, group="validation")
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
    @bounded_lru_cache(maxsize=VALIDATION_CACHE_SIZE, group="validation")
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
            if len(part) > 1 and part[0] == "0":
                return False
            try:
                if not 0 <= int(part) <= 255:
                    return False
            except ValueError:
                return False
        return True

    @staticmethod
    @bounded_lru_cache(maxsize=VALIDATION_CACHE_SIZE, group="validation")
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
            port_number(port)
        except ValueError:
            return False
        return True

    @staticmethod
    @bounded_lru_cache(maxsize=VALIDATION_CACHE_SIZE, group="validation")
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
    @bounded_lru_cache(maxsize=VALIDATION_CACHE_SIZE, group="validation")
    def is_valid_fragment(fragment: str) -> bool:
        """Validate URL fragment.

        Args:
            fragment: The fragment string.
        Returns:
            True if valid, False otherwise.
        """
        if not isinstance(fragment, str) or len(unquote(fragment)) > MAX_FRAGMENT_LENGTH:
            return False
        return bool(compiled_regex["fragment"].fullmatch(fragment))

    @staticmethod
    @bounded_lru_cache(maxsize=VALIDATION_CACHE_SIZE, group="validation")
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

    @staticmethod
    def get_cache_info() -> dict[str, Any]:
        """Statistics for the validation caches."""
        return cache_info("validation")

    @staticmethod
    def clear_caches() -> dict[str, int]:
        """Clear the validation caches and return their previous sizes."""
        return clear_registered_caches("validation")


def is_valid_userinfo(value: str, max_length: int = MAX_USERINFO_LENGTH) -> bool:
    """Validate userinfo format safely without ReDoS risk.

    Args:
        value: The userinfo string to validate.
        max_length: Maximum allowed length.
    Returns:
        True if valid userinfo format, False otherwise.
    """
    # The limit applies to the decoded length, so a userinfo and its own
    # percent-encoded serialization (which can be up to 12x longer) are held
    # to the same bound and str(url) always re-parses.
    if not value or "@" in value or len(unquote(value)) > max_length:
        return False
    if ":" in value:
        username, _, _ = value.partition(":")
        return bool(username)
    return True


def scheme_rejection(
    scheme: str, *, allow_custom: bool, allowed: AbstractSet[str] = STANDARD_SCHEMES
) -> tuple[ErrorCode, str] | None:
    """Why ``scheme`` (lowercase, syntactically valid) is not allowed, or None if it is.

    The one scheme rule. The parser applies it while splitting a string, so
    a dangerous scheme is refused before anything after it is read; the
    security pass applies it to every validation, so ``validate(policy=...)``
    and derived URLs follow the same rule.
    """
    if allow_custom or scheme in allowed:
        return None
    if scheme in UNSAFE_SCHEMES:
        return (
            ErrorCode.UNSAFE_SCHEME,
            f"Scheme '{scheme}' can execute code or reach local resources; pass allow_custom_scheme=True to accept it.",
        )
    return (
        ErrorCode.UNSUPPORTED_SCHEME,
        f"Scheme '{scheme}' is not allowed ({', '.join(sorted(allowed))}); "
        "pass allow_custom_scheme=True, or add it to the policy's allowed_schemes.",
    )


class _URLValidation:
    """Validation of ``copy()`` overrides against the parser's component rules.

    Security validation is not here: it belongs to ``_security``, which sits
    above this module, and ``URL.validate`` calls it directly.
    """

    __slots__ = ()

    @staticmethod
    def validate_copy_overrides(overrides: dict[str, Any]) -> None:
        """Check what ``copy()`` overrides are, before they are normalized.

        Names, types, scheme syntax, control characters in the path and
        query, and a "#" in a query. The scheme allowlist is the policy's
        (``scheme_rejection``), applied when the derived URL is validated. Everything else about a component -- a host, userinfo,
        fragment or port that would not parse -- is rejected by the parser's
        own rules, which every derived URL goes through
        (``_parser.normalize_components``).
        """
        valid_keys = {"scheme", "host", "port", "path", "query", "fragment", "userinfo", "query_pairs"}
        invalid_keys = set(overrides.keys()) - valid_keys
        if invalid_keys:
            raise InvalidURLError(f"Invalid override(s): {', '.join(sorted(invalid_keys))}")

        for key in ("scheme", "host", "path", "query", "fragment"):
            if key in overrides and overrides[key] is not None:
                if not isinstance(overrides[key], str):
                    raise InvalidURLError(f"{key} must be a string")

        if "userinfo" in overrides and overrides["userinfo"] is not None:
            if not isinstance(overrides["userinfo"], str):
                raise InvalidURLError("userinfo must be a string")

        scheme = overrides.get("scheme")
        if scheme is not None and not Validator.is_valid_scheme(scheme.lower()):
            raise InvalidURLError(f"Invalid scheme: {scheme!r}", value=scheme, component="scheme")

        for key in ("path", "query"):
            value = overrides.get(key)
            if value is not None and not Validator.is_url_safe_string(value):
                raise InvalidURLError(f"{key} contains invalid control characters.", value=value, component=key)

        # A raw "#" in a query override would be emitted as-is and re-parse as
        # the start of a fragment, so the URL's .query and what str(url)
        # means would disagree. Encode it as %23, or use with_query_param().
        query = overrides.get("query")
        if query is not None and "#" in query:
            raise InvalidURLError("query must not contain '#'; encode it as %23.", value=query, component="query")


__all__ = ["Validator", "_URLValidation", "is_valid_userinfo", "scheme_rejection"]
