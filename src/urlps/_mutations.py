"""URL mutation and derivation helpers.

Internal module: handles copy(), with_*() methods that create new URL instances
with modified components, while preserving immutability guarantees.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from ._helpers import _normalize_port
from ._normalize import normalize_fragment, normalize_percent_encoding, normalize_userinfo
from ._parser import normalize_host
from ._security._unicode.uts46 import to_ascii
from .constants import DEFAULT_PORTS, OFFICIAL_SCHEMES
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

        _URLValidation.validate_copy_overrides(overrides, allow_custom_scheme=url._parser.custom_scheme)
        components = url._to_dict()
        components.update(overrides)
        components["port"] = _normalize_port(components.get("port"))

        # The overridable components are stored the way the parser would
        # store them, so the copy means exactly what its string means.
        scheme = components.get("scheme")
        if isinstance(scheme, str):
            components["scheme"] = scheme = scheme.lower()
        if "scheme" in overrides and "port" not in overrides:
            # The old scheme's default port is not an explicit choice; carrying
            # it over turned https://h/ into http://h:443/.
            old_default = DEFAULT_PORTS.get((url._scheme or "").lower())
            if url._port is not None and url._port == old_default:
                components["port"] = DEFAULT_PORTS.get(scheme or "")
        if overrides.get("userinfo") is not None:
            try:
                components["userinfo"] = normalize_userinfo(overrides["userinfo"])
            except UnicodeEncodeError as exc:
                raise InvalidURLError("Userinfo is not valid Unicode.", component="userinfo") from exc
        if overrides.get("query") is not None:
            components["query"] = normalize_percent_encoding(overrides["query"])
        if overrides.get("fragment") is not None:
            components["fragment"] = normalize_percent_encoding(overrides["fragment"])

        # copy() does not go through the parser, so the RFC 3986 §6.2.2
        # host normalization applied there has to be re-applied here --
        # otherwise with_host("EXAMPLE.COM.") would hand back a URL whose
        # .host defeats the caller's allowlist, reintroducing exactly the
        # bypass that normalization exists to close.
        #
        # IDNA-encode first, exactly as the parser does: storing the Unicode
        # spelling left .host non-ASCII (fullwidth "127.0.0.1" with
        # ideographic full stops) while every HTTP client and getaddrinfo map
        # it straight to loopback. validate_copy_overrides() has already
        # proven the host encodes, via the same to_ascii().
        host_override = components.get("host")
        if isinstance(host_override, str):
            if not host_override.isascii():
                host_override = to_ascii(host_override)
            components["host"] = normalize_host(host_override)
        _URLMutations._reconcile_query_components(components, overrides)

        # Import here to avoid circular import
        from .url import URL as URLClass

        new_url = object.__new__(URLClass)
        # Same reason as in __init__: __setattr__ reads this on every write.
        object.__setattr__(new_url, "_frozen", False)
        new_url.recognized_scheme = (scheme in OFFICIAL_SCHEMES) if scheme else None
        new_url._parser = url._parser
        new_url._builder = url._builder
        new_url._audit_manager = url._audit_manager
        new_url._debug = url._debug
        new_url._check_dns = url._check_dns
        new_url._check_phishing = url._check_phishing
        new_url._security_policy = url._security_policy
        new_url._correlation_id = url._correlation_id
        new_url._apply_parsed(components)
        _URLMutations._assert_round_trip(new_url)
        new_url._security_findings = []
        new_url._security_findings = new_url.validate(raise_on_error=True)
        object.__setattr__(new_url, "_frozen", True)
        return new_url

    @staticmethod
    def _assert_round_trip(url: URL) -> None:
        """Refuse a derived URL whose string would re-parse into different components.

        A copy is assembled from components rather than parsed, so nothing
        else guarantees that ``str(url)`` means what ``url`` reports -- and
        when it does not, the security checks validated one URL and the
        caller sends another. The path is not compared: it is always
        percent-encoded on output and cannot move the authority. Scheme-less
        URLs are skipped: they serialize without "//" by design (``build()``).
        """
        if not url._scheme:
            return
        from ._parser import Parser

        parser = Parser()
        parser.custom_scheme = url._parser.custom_scheme
        try:
            reparsed = parser.parse(url.as_string())
        except InvalidURLError as exc:
            raise InvalidURLError(f"Derived URL does not re-parse: {exc.message}", component="url") from exc

        def effective_port(scheme: Any, port: Any) -> Any:
            return port if port is not None else DEFAULT_PORTS.get(str(scheme or "").lower())

        def canonical_fragment(fragment: Any) -> Any:
            # An empty fragment is not serialized; "" and None mean the same.
            return normalize_fragment(fragment) if fragment else None

        comparisons = (
            ("scheme", url._scheme, reparsed["scheme"]),
            ("userinfo", url._userinfo, reparsed["userinfo"]),
            ("host", url._host, reparsed["host"]),
            ("port", effective_port(url._scheme, url._port), effective_port(reparsed["scheme"], reparsed["port"])),
            ("query", url._query, reparsed["query"]),
            ("fragment", canonical_fragment(url._fragment), canonical_fragment(reparsed["fragment"])),
        )
        changed = [name for name, ours, theirs in comparisons if ours != theirs]
        if changed:
            raise InvalidURLError(
                f"Derived URL does not round-trip: re-parsing it would change {', '.join(changed)}.",
                component=changed[0],
            )

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
