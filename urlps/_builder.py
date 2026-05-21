from __future__ import annotations

from typing import Any, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import quote, quote_plus, unquote_plus
from functools import lru_cache

from .constants import DEFAULT_PORTS, OfficialSchemes
from .exceptions import (
    URLBuildError,
    PortValidationError,
)
from ._patterns import PATTERNS

QueryPairs = List[Tuple[str, Optional[str]]]

_PERCENT_ENCODE_PATTERN = PATTERNS["percent_encode"]


@lru_cache(maxsize=8192)
def _encode_for_query(value: str, safe: str) -> str:
    """Encode a query component with quote_plus and normalize percent-encodings to uppercase.

    Performance: Cached across serialize_query calls to amortize the cost
    of percent-encoding for repeated keys/values.
    """
    encoded = quote_plus(value, safe=safe)
    return _PERCENT_ENCODE_PATTERN.sub(lambda m: m.group(0).upper(), encoded)


class Builder:
    """URL composition and building utilities.

    This class provides methods for building URLs from components,
    serializing query parameters, and manipulating URL parts.

    Class Attributes:
        PATH_SAFE: Characters that don't need percent-encoding in paths.
        QUERY_SAFE: Characters that don't need percent-encoding in query strings.
        FRAGMENT_SAFE: Characters that don't need percent-encoding in fragments.

    Example:
        >>> builder = Builder()
        >>> builder.compose({"scheme": "https", "host": "example.com", "path": "/api"})
        'https://example.com/api'
    """

    PATH_SAFE = "-._~!$&'()*+,;=:@%"
    QUERY_SAFE = "-._~:/?@!$&'()*+,;="
    FRAGMENT_SAFE = "-._~!$&'()*+,;=:@/?"

    def compose(self, components: Mapping[str, Any]) -> str:
        """Compose a URL string from component parts.

        Assembles a complete URL from individual components, handling proper
        encoding and normalization according to RFC 3986.

        Args:
            components: A mapping containing URL components:
                - scheme (str, optional): URL scheme (e.g., 'https', 'http')
                - host (str, optional): Hostname or IP address
                - port (int, optional): Port number (omitted if default for scheme)
                - path (str, optional): URL path (normalized, defaults to '/')
                - query (str, optional): Raw query string
                - query_pairs (list, optional): List of (key, value) tuples (preferred over query)
                - fragment (str, optional): Fragment identifier
                - userinfo (str, optional): User info in 'user:pass' format

        Returns:
            The composed URL string.

        Raises:
            URLBuildError: If host is required but not provided.
            PortValidationError: If port is set without a host.

        Note:
            - If both `query` and `query_pairs` are provided, `query_pairs` takes precedence.
            - Default ports (80 for http, 443 for https) are automatically omitted.
            - Paths are normalized (e.g., '/a/../b' becomes '/b').
        """
        scheme = components.get("scheme")
        userinfo = components.get("userinfo")
        host = components.get("host")
        port = components.get("port")
        path = components.get("path") or ""
        fragment = components.get("fragment")
        query = components.get("query")
        query_pairs: QueryPairs = components.get("query_pairs") or []

        normalized_path = self.normalize_path(path)
        if not normalized_path and host:
            normalized_path = "/"
        serialized_query = query
        if query_pairs:
            serialized_query = self.serialize_query(query_pairs)

        url = ""
        if scheme:
            url += f"{scheme}://"
        netloc = self.build_netloc(userinfo, host, port, scheme)
        if netloc:
            url += netloc
        elif scheme and scheme.lower() not in {OfficialSchemes.FILE.value}:
            raise URLBuildError("Host is required when building absolute URLs.")

        url += normalized_path

        if serialized_query is not None:
            url += f"?{serialized_query}"
        if fragment:
            url += f"#{self.percent_encode(str(fragment), safe=self.FRAGMENT_SAFE)}"
        return url

    def compose_secure(
        self,
        components: Mapping[str, Any],
        *,
        policy: Any = None,
        check_dns: bool = False,
        check_phishing: bool = False,
        correlation_id: Optional[str] = None,
    ) -> str:
        """Compose then validate a URL under a security policy."""
        from . import parse_url

        url = self.compose(components)
        validated = parse_url(
            url,
            policy=policy,
            check_dns=check_dns,
            check_phishing=check_phishing,
            correlation_id=correlation_id,
        )
        return validated.as_string()

    def build_netloc(
        self,
        userinfo: Optional[str],
        host: Optional[str],
        port: Optional[int],
        scheme: Optional[str]
    ) -> str:
        """Build the network location (authority) component of a URL.

        Constructs the netloc string in the format: [userinfo@]host[:port]

        Args:
            userinfo: Optional user information (e.g., 'user:password').
            host: Hostname or IP address. Required if port is provided.
            port: Optional port number. Omitted if it's the default for the scheme.
            scheme: URL scheme, used to determine default ports.

        Returns:
            The netloc string, or empty string if no host is provided.

        Raises:
            PortValidationError: If port is provided without a host.

        Example:
            >>> builder = Builder()
            >>> builder.build_netloc('user:pass', 'example.com', 8080, 'https')
            'user:pass@example.com:8080'
            >>> builder.build_netloc(None, 'example.com', 443, 'https')
            'example.com'  # Port 443 omitted for https
        """
        if not host:
            if port is not None:
                raise PortValidationError("Port cannot be set without a host.", value=port, component="port")
            return userinfo or ""
        parts = []
        if userinfo:
            parts.append(f"{userinfo}@")
        parts.append(host)
        display_port = port
        if scheme and display_port is not None and DEFAULT_PORTS.get(scheme.lower()) == display_port:
            display_port = None
        if display_port is not None:
            parts.append(f":{display_port}")
        return "".join(parts)

    def normalize_path(self, path: Optional[str]) -> str:
        """Normalize a URL path according to RFC 3986.

        Performs the following normalizations:
        - Resolves '.' (current directory) segments
        - Resolves '..' (parent directory) segments
        - Percent-encodes characters that need encoding
        - Preserves trailing slashes when appropriate
        - Normalizes percent-encoding to uppercase

        Args:
            path: The path string to normalize, or None/empty string.

        Returns:
            The normalized path string. Returns empty string for None/empty input.
            Returns '/' for absolute paths that resolve to root.

        Example:
            >>> builder = Builder()
            >>> builder.normalize_path('/a/b/../c')
            '/a/c'
            >>> builder.normalize_path('/a/./b')
            '/a/b'
            >>> builder.normalize_path('/a/b/')
            '/a/b/'
        """
        if path is None or path == "":
            return ""
        absolute = path.startswith("/")
        trailing_slash = path.endswith("/")

        # Check if path ends with "." or "./" which should result in trailing slash
        ends_with_dot_segment = path.endswith("/.") or path.endswith("/./")

        segments: List[str] = []
        for segment in path.split("/"):
            if not segment or segment == ".":
                continue
            elif segment == "..":
                if segments:
                    segments.pop()
            else:
                segments.append(self.percent_encode(segment, safe=self.PATH_SAFE))

        if not segments:
            return "/" if absolute else ""

        normalized = "/".join(segments)
        if absolute:
            normalized = "/" + normalized
        # Preserve trailing slash when originally present, or when path ends with "." segment
        if (trailing_slash or ends_with_dot_segment) and normalized != "/":
            normalized += "/"
        return normalized

    def percent_encode(self, value: str, *, safe: str) -> str:
        # Use urllib.quote to percent-encode then normalize percent-encoding to uppercase hex
        return self._percent_encode_cached(value, safe)

    @staticmethod
    @lru_cache(maxsize=1024)
    def _percent_encode_cached(value: str, safe: str) -> str:
        """Cached percent-encoding with uppercase hex normalization."""
        encoded = quote(value, safe=safe)
        # Uppercase percent-encodings to canonical form using pre-compiled pattern
        return _PERCENT_ENCODE_PATTERN.sub(lambda m: m.group(0).upper(), encoded)

    @staticmethod
    def _fast_unquote_plus(value: str) -> str:
        """Optimized URL decoding with fast-path for strings without encoding.

        Performance: Skips expensive unquote_plus() for strings without % or +.
        """
        if '%' not in value and '+' not in value:
            return value
        return unquote_plus(value)

    def parse_query(self, query: Optional[str]) -> QueryPairs:
        """Parse a query string into a list of key-value pairs.

        Splits the query string on '&' delimiters and decodes each key-value pair.
        Values are URL-decoded using plus-to-space conversion.

        Args:
            query: The query string to parse (without the leading '?'),
                   or None/empty string.

        Returns:
            A list of (key, value) tuples. Value is None for keys without '='.

        Raises:
            URLBuildError: If a query key is empty.

        Example:
            >>> builder = Builder()
            >>> builder.parse_query('foo=bar&baz=qux')
            [('foo', 'bar'), ('baz', 'qux')]
            >>> builder.parse_query('flag&key=value')
            [('flag', None), ('key', 'value')]
            >>> builder.parse_query('name=hello+world')
            [('name', 'hello world')]

        Performance: Uses fast-path decoding for strings without percent-encoding.
        """
        if query is None or query == "":
            return []
        pairs: QueryPairs = []
        for chunk in query.split("&"):
            if chunk == "":
                continue
            # Use partition for better performance
            key_raw, sep, value_raw = chunk.partition("=")
            key = self._fast_unquote_plus(key_raw)
            if not key:
                raise URLBuildError("Query keys must be non-empty.", value=chunk, component="query")
            value = self._fast_unquote_plus(value_raw) if sep else None
            pairs.append((key, value))
        return pairs

    def serialize_query(self, params: QueryPairs) -> str:
        """Serialize query pairs to a query string."""
        return self._serialize_query_impl(params, self.QUERY_SAFE)

    def _serialize_query_impl(self, params: QueryPairs, query_safe: str) -> str:
        """Shared implementation for query serialization."""
        if not params:
            return ""
        encoded: List[str] = []
        # Use module-level LRU cache to reduce repeated encoding work across calls
        def encode(val: str) -> str:
            return _encode_for_query(val, query_safe)
        for key, value in params:
            encoded_key = encode(key)
            if value is None:
                encoded.append(encoded_key)
            else:
                encoded_value = encode(str(value))
                encoded.append(f"{encoded_key}={encoded_value}")
        return "&".join(encoded)

    def add_param(self, query: Optional[str], key: str, value: Optional[str] = None) -> str:
        """Add a parameter to a query string.

        Appends a new key-value pair to the existing query string.
        Does not check for duplicate keys.

        Args:
            query: The existing query string (without '?'), or None.
            key: The parameter key to add.
            value: The parameter value, or None for a value-less key.

        Returns:
            The new query string with the parameter added.

        Example:
            >>> builder = Builder()
            >>> builder.add_param('foo=bar', 'baz', 'qux')
            'foo=bar&baz=qux'
            >>> builder.add_param(None, 'key', 'value')
            'key=value'
        """
        pairs = self.parse_query(query)
        pairs.append((key, value))
        return self.serialize_query(pairs)

    def remove_param(self, query: Optional[str], key: str) -> str:
        """Remove all occurrences of a parameter from a query string.

        Removes ALL key-value pairs matching the given key.

        Args:
            query: The existing query string (without '?'), or None.
            key: The parameter key to remove.

        Returns:
            The new query string with all matching parameters removed.

        Example:
            >>> builder = Builder()
            >>> builder.remove_param('foo=1&bar=2&foo=3', 'foo')
            'bar=2'
            >>> builder.remove_param('a=1&b=2', 'c')
            'a=1&b=2'
        """
        pairs = [(k, v) for k, v in self.parse_query(query) if k != key]
        return self.serialize_query(pairs)

    def merge_params(self, query: Optional[str], updates: Mapping[str, Any]) -> str:
        """Merge new parameters into a query string.

        Adds new key-value pairs from the updates mapping. Does not remove
        or replace existing parameters with the same keys.

        Args:
            query: The existing query string (without '?'), or None.
            updates: A mapping of keys to values. Values can be:
                - str: Added as a single parameter
                - None: Added as a value-less key
                - Iterable (not str/bytes): Each item added as separate parameter

        Returns:
            The new query string with merged parameters.

        Example:
            >>> builder = Builder()
            >>> builder.merge_params('a=1', {'b': '2', 'c': '3'})
            'a=1&b=2&c=3'
            >>> builder.merge_params('a=1', {'arr': ['x', 'y']})
            'a=1&arr=x&arr=y'
        """
        pairs = self.parse_query(query)
        for key, value in updates.items():
            if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
                for child in value:
                    pairs.append((key, None if child is None else str(child)))
            else:
                pairs.append((key, None if value is None else str(value)))
        return self.serialize_query(pairs)


__all__ = [
    "Builder",
    "QueryPairs",
]
