"""URL mutation and derivation helpers.

Internal module: handles copy(), with_*() methods that create new URL instances
with modified components, while preserving immutability guarantees.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from ._helpers import _normalize_port
from ._parser import normalize_host
from .constants import DEFAULT_PORTS
from .exceptions import InvalidURLError

if TYPE_CHECKING:
    from .url import URL


class _URLMutations:
    """URL derivation methods (copy, with_*).

    All methods return new URL instances. The original URL remains unchanged.
    """

    __slots__ = ()

    @staticmethod
    def copy(url: URL, **overrides: Any) -> URL:
        """Create a copy with optional component overrides.

        Args:
            url: The URL instance to copy from.
            overrides: Components to override.

        Returns:
            A new URL instance with the specified overrides.

        Raises:
            InvalidURLError: If overrides are invalid.
        """
        from ._validation import _URLValidation

        _URLValidation.validate_copy_overrides(overrides)
        components = url._to_dict()
        components.update(overrides)
        components["port"] = _normalize_port(components.get("port"))

        # copy() does not go through the parser, so the RFC 3986 §6.2.2
        # host normalization applied there has to be re-applied here --
        # otherwise with_host("EXAMPLE.COM.") would hand back a URL whose
        # .host defeats the caller's allowlist, reintroducing exactly the
        # bypass that normalization exists to close.
        host_override = components.get("host")
        if isinstance(host_override, str):
            components["host"] = normalize_host(host_override)
        _URLMutations._reconcile_query_components(components, overrides)

        # Import here to avoid circular import
        from .url import URL as URLClass

        new_url = object.__new__(URLClass)
        # Same reason as in __init__: __setattr__ reads this on every write.
        object.__setattr__(new_url, "_frozen", False)
        new_url.recognized_scheme = url.recognized_scheme
        new_url._parser = url._parser
        new_url._builder = url._builder
        new_url._audit_manager = url._audit_manager
        new_url._debug = url._debug
        new_url._check_dns = url._check_dns
        new_url._check_phishing = url._check_phishing
        new_url._security_policy = url._security_policy
        new_url._correlation_id = url._correlation_id
        new_url._apply_parsed(components)
        new_url._security_findings = []
        new_url._security_findings = new_url.validate(raise_on_error=True)
        object.__setattr__(new_url, "_frozen", True)
        return new_url

    @staticmethod
    def _reconcile_query_components(
        components: dict[str, Any],
        overrides: Mapping[str, Any],
    ) -> None:
        """Keep ``query`` and ``query_pairs`` from disagreeing after an override.

        They are two representations of one value. Overriding only one of them
        would otherwise leave the copy carrying the *previous* value in the
        other, so the stale one has to be re-derived from whichever the caller
        actually supplied.
        """
        overrode_query = "query" in overrides
        overrode_pairs = "query_pairs" in overrides
        if overrode_query == overrode_pairs:
            # Neither (already consistent) or both (caller owns both).
            return

        # Need to access builder from components context
        # This is passed through the copy flow
        from ._builder import Builder

        builder = Builder()
        if overrode_query:
            query = components.get("query")
            components["query_pairs"] = builder.parse_query(query) if query else []
        else:
            pairs = components.get("query_pairs") or []
            components["query"] = builder.serialize_query(pairs) if pairs else None

    @staticmethod
    def with_scheme(url: URL, scheme: str | None) -> URL:
        """Return new URL with different scheme."""
        if scheme is not None and not isinstance(scheme, str):
            raise InvalidURLError(f"Invalid scheme: {scheme!r}")
        return _URLMutations.copy(url, scheme=scheme)

    @staticmethod
    def with_host(url: URL, host: str | None) -> URL:
        """Return new URL with different host."""
        return _URLMutations.copy(url, host=host)

    @staticmethod
    def with_port(url: URL, port: int | None) -> URL:
        """Return new URL with different port."""
        return _URLMutations.copy(url, port=port)

    @staticmethod
    def with_path(url: URL, path: str) -> URL:
        """Return new URL with different path."""
        return _URLMutations.copy(url, path=path)

    @staticmethod
    def with_query(url: URL, query: str | None) -> URL:
        """Return new URL with different query string."""
        return _URLMutations.copy(url, query=query)

    @staticmethod
    def with_fragment(url: URL, fragment: str | None) -> URL:
        """Return new URL with different fragment."""
        return _URLMutations.copy(url, fragment=fragment)

    @staticmethod
    def with_userinfo(url: URL, userinfo: str | None) -> URL:
        """Return new URL with different userinfo."""
        return _URLMutations.copy(url, userinfo=userinfo)

    @staticmethod
    def with_netloc(url: URL, netloc: str) -> URL:
        """Return new URL with different netloc (userinfo@host:port)."""
        from ._parser import Parser

        parser = Parser()
        userinfo, host, port = parser.parse_netloc(netloc, require_host=bool(netloc))
        if port is None and url._scheme and host:
            port = DEFAULT_PORTS.get(url._scheme.lower())
        return _URLMutations.copy(url, userinfo=userinfo, host=host, port=port)

    @staticmethod
    def with_query_param(url: URL, key: str, value: str | None = None) -> URL:
        """Return new URL with added query parameter."""
        from ._helpers import _check_type

        _check_type(key, str, "key")
        normalized_key = str(key)
        new_query = url._builder.add_param(url._query, normalized_key, value)
        return _URLMutations.copy(url, query=new_query)

    @staticmethod
    def without_query_param(url: URL, key: str) -> URL:
        """Return new URL with query parameter removed."""
        from ._helpers import _check_type

        _check_type(key, str, "key")
        normalized_key = str(key)
        new_query = url._builder.remove_param(url._query, normalized_key)
        return _URLMutations.copy(url, query=new_query)

    @staticmethod
    def without_query(url: URL) -> URL:
        """Return new URL without query string or fragment."""
        return _URLMutations.copy(url, query=None, query_pairs=[], fragment=None)

    @staticmethod
    def same_origin(url: URL, other: URL) -> bool:
        """Check if this URL has the same origin as another URL."""
        return url.origin == other.origin
