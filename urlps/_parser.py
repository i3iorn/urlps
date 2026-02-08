"""URL parsing module with stateless functions and Parser class."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote_plus
from functools import lru_cache

from ._builder import Builder, QueryPairs
from ._components import ParseResult
from .constants import (
    DEFAULT_PORTS, SCHEMES_NO_PORT, OFFICIAL_SCHEMES, UNSAFE_SCHEMES,
    MAX_SCHEME_LENGTH, MAX_HOST_LENGTH, MAX_PATH_LENGTH,
    MAX_QUERY_LENGTH, MAX_FRAGMENT_LENGTH,
)
from .exceptions import (
    URLParseError, HostValidationError, PortValidationError,
    UserInfoParsingError, MissingHostError, UnsupportedSchemeError,
    FragmentEncodingError, QueryParsingError,
)
from ._validation import Validator, is_valid_userinfo

_builder_singleton = Builder()


def parse_scheme(url: str, allow_custom: bool = False) -> Tuple[Optional[str], str, Optional[bool]]:
    """Parse scheme from URL. Returns (scheme, remainder, recognized_scheme)."""
    if "://" in url:
        scheme_candidate, _, remainder = url.partition("://")
    elif ":" in url:
        scheme_candidate, _, remainder = url.partition(":")
        if remainder and not remainder.startswith("/") and not remainder.startswith("?") and not remainder.startswith("#"):
            if not Validator.is_valid_scheme(scheme_candidate.lower()):
                return None, url, None
    else:
        return None, url, None

    if len(scheme_candidate) > MAX_SCHEME_LENGTH:
        raise URLParseError(f"Scheme exceeds maximum length of {MAX_SCHEME_LENGTH}.", value=scheme_candidate, component="scheme")

    scheme_lower = scheme_candidate.lower()
    if scheme_lower in UNSAFE_SCHEMES and not allow_custom:
        raise URLParseError(f"Scheme '{scheme_candidate}' requires custom_scheme=True", value=scheme_candidate, component="scheme")
    if scheme_lower in OFFICIAL_SCHEMES:
        return scheme_lower, remainder, True
    if Validator.is_valid_scheme(scheme_lower) or allow_custom:
        return scheme_lower, remainder, False
    raise URLParseError(f"Invalid URL scheme: {scheme_candidate}", value=scheme_candidate, component="scheme")


def split_fragment(url: str) -> Tuple[str, Optional[str]]:
    """Split fragment from URL."""
    if "#" not in url:
        return url, None
    base, _, fragment = url.partition("#")
    return base, fragment


def split_query(url: str) -> Tuple[str, Optional[str]]:
    """Split query string from URL."""
    if "?" not in url:
        return url, None
    base, _, query = url.partition("?")
    return base, query


def split_authority(url: str) -> Tuple[str, str]:
    """Split authority from path in URL."""
    if not url:
        return "", ""
    if "/" in url:
        authority, _, path = url.partition("/")
        return authority, f"/{path}"
    return url, ""


def parse_userinfo(authority: str) -> Tuple[Optional[str], str]:
    """Parse userinfo from authority."""
    if not authority or "@" not in authority:
        return None, authority or ""
    auth_segment, _, host = authority.partition("@")
    if not is_valid_userinfo(auth_segment):
        raise UserInfoParsingError("Invalid authentication section in URL.", value=auth_segment, component="userinfo")
    return auth_segment, host


def parse_port(candidate: str) -> int:
    """Parse and validate port number.

    Args:
        candidate: Port string to parse (must be numeric)

    Returns:
        Validated port number as integer

    Raises:
        PortValidationError: If port is non-numeric or out of valid range (1-65535)
    """
    if not candidate or not candidate.isdigit():
        raise PortValidationError(
            f"Port must be a positive integer. Received: {candidate!r}",
            value=candidate,
            component="port"
        )
    if not Validator.is_valid_port(candidate):
        raise PortValidationError(
            f"Port must be between 1 and 65535. Received: {candidate}",
            value=candidate,
            component="port"
        )
    return int(candidate)


def parse_ipv6_host(host_candidate: str) -> Tuple[str, Optional[int]]:
    """Parse IPv6 host with optional port."""
    closing = host_candidate.find("]")
    if closing == -1:
        raise HostValidationError("Invalid IPv6 host segment.", value=host_candidate, component="host")
    host_literal = host_candidate[:closing + 1]
    remainder = host_candidate[closing + 1:]
    if not Validator.is_valid_ipv6(host_literal):
        raise HostValidationError("Invalid IPv6 address format.", value=host_literal, component="host")
    port = None
    if remainder.startswith(":"):
        port = parse_port(remainder[1:])
    elif remainder:
        raise HostValidationError("Unexpected characters after IPv6 literal.", value=remainder, component="host")
    return host_literal, port


def parse_regular_host(host_candidate: str) -> Tuple[str, Optional[int]]:
    """Parse regular hostname with optional port."""
    host_part, sep, port_part = host_candidate.partition(":")
    if not host_part:
        raise MissingHostError("Host cannot be empty.", value=host_part, component="host")
    if "." in host_part and host_part.replace(".", "").replace("-", "").isdigit():
        if not Validator.is_valid_ipv4(host_part):
            raise HostValidationError("Invalid IPv4 address format.", value=host_part, component="host")
        return host_part, parse_port(port_part) if sep else None
    if not Validator.is_valid_host(host_part):
        raise HostValidationError("Host contains invalid characters.", value=host_part, component="host")
    if any(ord(c) > 127 for c in host_part):
        try:
            ascii_host = host_part.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise HostValidationError("Unable to IDNA-encode host.", value=host_part, component="host") from exc
    else:
        ascii_host = host_part
    return ascii_host, parse_port(port_part) if sep else None


def parse_host(host_candidate: str, require_host: bool = False) -> Tuple[Optional[str], Optional[int]]:
    """Parse host and port from candidate string."""
    if not host_candidate:
        if require_host:
            raise MissingHostError("Host is required for absolute URLs.", value=host_candidate, component="host")
        return None, None
    host_candidate = host_candidate.strip()
    if len(host_candidate) > MAX_HOST_LENGTH:
        raise HostValidationError(f"Host exceeds maximum length of {MAX_HOST_LENGTH}.", value=host_candidate, component="host")
    if host_candidate.startswith("["):
        return parse_ipv6_host(host_candidate)
    return parse_regular_host(host_candidate)


@lru_cache(maxsize=1024)
def normalize_path(path_candidate: str) -> str:
    """Normalize URL path by resolving . and .. segments.

    Performance: LRU cached to avoid re-normalizing common paths.
    """
    if not path_candidate:
        return ""
    if len(path_candidate) > MAX_PATH_LENGTH:
        raise URLParseError(f"Path exceeds maximum length of {MAX_PATH_LENGTH}.", value=path_candidate, component="path")
    absolute = path_candidate.startswith("/")
    trailing = path_candidate.endswith("/") or path_candidate.endswith("/.") or path_candidate.endswith("/./")
    segments: List[str] = []
    for seg in path_candidate.split("/"):
        if not seg or seg == ".":
            continue
        elif seg == "..":
            if segments:
                segments.pop()
        else:
            segments.append(seg)
    if not segments:
        return "/" if absolute else ""
    normalized = "/".join(segments)
    if absolute:
        normalized = "/" + normalized
    if trailing and normalized != "/":
        normalized += "/"
    return normalized


def _fast_unquote_plus(value: str) -> str:
    """Optimized URL decoding with fast-path for strings without encoding.

    Performance: Skips expensive unquote_plus() for strings without % or +.
    """
    if '%' not in value and '+' not in value:
        return value
    return unquote_plus(value)


def _validate_query_string_batch(query: str) -> bool:
    """Batch validation of entire query string for control characters.

    Performance: Single regex pass instead of per-parameter validation.
    Returns True if valid, False otherwise.
    """
    return Validator.is_url_safe_string(query)


def parse_query_string(query_candidate: Optional[str]) -> Tuple[Optional[str], QueryPairs]:
    """Parse query string into normalized string and pairs.

    Performance optimizations:
    - Batch validation of entire query string
    - Fast-path decoding for strings without percent-encoding
    """
    if query_candidate is None:
        return None, []
    if query_candidate == "":
        return "", []
    if len(query_candidate) > MAX_QUERY_LENGTH:
        raise QueryParsingError(f"Query exceeds maximum length of {MAX_QUERY_LENGTH}.", value=query_candidate, component="query")

    if not _validate_query_string_batch(query_candidate):
        raise QueryParsingError("Query string contains invalid characters.", value=query_candidate, component="query")

    pairs: QueryPairs = []
    for chunk in query_candidate.split("&"):
        if not chunk:
            continue
        key_raw, sep, value_raw = chunk.partition("=")
        key = _fast_unquote_plus(key_raw)
        if not key:
            raise QueryParsingError("Query keys must be non-empty.", value=chunk, component="query")
        pairs.append((key, _fast_unquote_plus(value_raw) if sep else None))

    return _builder_singleton.serialize_query(pairs), pairs


def parse_fragment_string(fragment_candidate: Optional[str]) -> Optional[str]:
    """Parse and validate fragment."""
    if fragment_candidate is None:
        return None
    if len(fragment_candidate) > MAX_FRAGMENT_LENGTH:
        raise FragmentEncodingError(f"Fragment exceeds maximum length of {MAX_FRAGMENT_LENGTH}.", value=fragment_candidate, component="fragment")
    if not Validator.is_valid_fragment(fragment_candidate):
        raise FragmentEncodingError("Fragment contains invalid characters.", value=fragment_candidate, component="fragment")
    return fragment_candidate


def apply_port_defaults(scheme: Optional[str], port: Optional[int], host: Optional[str]) -> Optional[int]:
    """Apply default ports and validate scheme/port combinations."""
    if scheme and scheme.lower() in SCHEMES_NO_PORT and port is not None:
        raise UnsupportedSchemeError(f"Scheme '{scheme}' does not allow explicit ports.", value=scheme, component="scheme/port")
    if port is not None and host is None and (not scheme or scheme.lower() != "file"):
        raise PortValidationError("Port cannot be set without a host.", value=port, component="port")
    if port is not None:
        return port
    return DEFAULT_PORTS.get(scheme.lower()) if scheme else None


def parse_url(url: str, allow_custom_scheme: bool = False) -> ParseResult:
    """Parse a URL string into a ParseResult with all components."""
    if not isinstance(url, str):
        raise URLParseError(
            f"URL must be a string, not {type(url).__name__}.",
            value=url,
            component="url"
        )
    if not url.strip():
        raise URLParseError(
            f"URL cannot be empty or whitespace-only. Received: {url!r}",
            value=url,
            component="url"
        )
    working = url.strip()
    scheme, remainder, recognized = parse_scheme(working, allow_custom_scheme)
    
    if not scheme and remainder.startswith("//"):
        remainder = remainder[2:]

    remainder, fragment_str = split_fragment(remainder)
    remainder, query_str = split_query(remainder)

    if (scheme and "://" in working) or (not scheme and url.startswith("//")):
        authority, path_candidate = split_authority(remainder)
    else:
        authority, path_candidate = "", remainder

    userinfo, host_candidate = parse_userinfo(authority)
    require_host = bool(scheme) and scheme is not None and scheme.lower() != "file" and "://" in working if scheme else False
    host, port = parse_host(host_candidate, require_host=require_host)
    port = apply_port_defaults(scheme, port, host)
    path = normalize_path(path_candidate)
    if host and not path:
        path = "/"
    query, query_pairs = parse_query_string(query_str)
    fragment = parse_fragment_string(fragment_str)

    return ParseResult(
        scheme=scheme, userinfo=userinfo, host=host, port=port, path=path,
        query=query, fragment=fragment, query_pairs=list(query_pairs),
        recognized_scheme=recognized,
    )


class Parser:
    """URL parser class for backward compatibility."""
    __slots__ = ('_custom_scheme', '_recognized_scheme', '_query_pairs', '_port')

    def __init__(self) -> None:
        self._custom_scheme = False
        self._recognized_scheme: Optional[bool] = None
        self._query_pairs: QueryPairs = []
        self._port: Optional[int] = None

    @property
    def custom_scheme(self) -> bool:
        return self._custom_scheme

    @custom_scheme.setter
    def custom_scheme(self, value: bool) -> None:
        self._custom_scheme = value

    @property
    def recognized_scheme(self) -> Optional[bool]:
        return self._recognized_scheme

    @property
    def query_pairs(self) -> QueryPairs:
        return self._query_pairs

    @property
    def port(self) -> Optional[int]:
        return self._port

    def parse(self, maybe_url: str) -> Dict[str, Optional[Any]]:
        """Parse a URL string into its components."""
        result = parse_url(maybe_url, allow_custom_scheme=self._custom_scheme)
        self._recognized_scheme = result.recognized_scheme
        self._query_pairs = list(result.query_pairs)
        self._port = result.port
        return result.to_dict()

    def parse_netloc(self, netloc: str, *, require_host: bool = False) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """Parse a netloc string into userinfo, host, and port."""
        userinfo, host_candidate = parse_userinfo(netloc)
        host, port = parse_host(host_candidate, require_host=require_host)
        return userinfo, host, apply_port_defaults(None, port, host)


def get_cache_info() -> dict:
    """Get statistics about parser caches.

    Returns:
        Dictionary with cache statistics for cached functions.
    """
    stats = {}
    if hasattr(normalize_path, 'cache_info'):
        info = normalize_path.cache_info()
        stats['normalize_path'] = {
            'hits': info.hits,
            'misses': info.misses,
            'maxsize': info.maxsize,
            'currsize': info.currsize,
        }
    return stats


def clear_caches() -> dict:
    """Clear all parser caches and return previous sizes.

    Returns:
        Dictionary mapping function names to previous cache sizes.
    """
    previous = {}
    if hasattr(normalize_path, 'cache_info'):
        previous['normalize_path'] = normalize_path.cache_info().currsize
        if hasattr(normalize_path, 'cache_clear'):
            normalize_path.cache_clear()
    return previous


__all__ = [
    "parse_url", "parse_scheme", "parse_host", "parse_userinfo", "normalize_path",
    "parse_query_string", "parse_fragment_string", "Parser",
    "get_cache_info", "clear_caches",
]
