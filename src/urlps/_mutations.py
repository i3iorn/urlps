"""URL derivation: ``copy()`` and the ``with_*()`` methods.

Works on :class:`~urlps._components.URLParts` and the URL's context; a new
URL is built through ``type(url)._from_parts`` -- the same constructor path
every derived URL takes -- so this module never imports ``URL`` itself.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from ._components import URLParts
from ._helpers import _normalize_port
from ._normalize import normalize_percent_encoding, normalize_userinfo
from ._parser import normalize_path, parse_netloc
from ._parser import parse_url as parse_components
from ._security._unicode.uts46 import canonical_host
from ._validation import _URLValidation
from .constants import DEFAULT_PORTS, OFFICIAL_SCHEMES
from .exceptions import InvalidURLError

if TYPE_CHECKING:
    from ._builder import Builder
    from .url import URL, _URLContext


def derive(url: URL, overrides: Mapping[str, Any]) -> URL:
    """Return a new URL: ``url`` with ``overrides`` applied, validated under its own policy."""
    context = url._context
    _URLValidation.validate_copy_overrides(dict(overrides), allow_custom_scheme=context.allow_custom_scheme)
    components = url._parts.as_mapping()
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
        old_default = DEFAULT_PORTS.get((url._parts.scheme or "").lower())
        if url._parts.port is not None and url._parts.port == old_default:
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
    if isinstance(overrides.get("path"), str):
        # Exactly the parser's path normalization: .path, str(url) and a
        # re-parse of it then agree ("/a/../b" is "/b" in all three).
        components["path"] = normalize_path(overrides["path"])

    # The parser's host form (IDNA, then RFC 3986 §6.2.2): with_host("EXAMPLE.COM.")
    # must not hand back a .host that defeats an allowlist, and a Unicode
    # spelling of 127.0.0.1 must not stay un-encoded while every client maps
    # it to loopback. validate_copy_overrides() has already proven the host
    # encodes.
    host = components.get("host")
    if isinstance(host, str):
        components["host"] = canonical_host(host)
    _reconcile_query_components(components, overrides, context.builder)

    parts = URLParts(
        scheme=components.get("scheme"),
        userinfo=components.get("userinfo"),
        host=components.get("host"),
        port=components.get("port"),
        path=components.get("path") or "",
        query=components.get("query"),
        fragment=components.get("fragment"),
        query_pairs=tuple(components.get("query_pairs") or ()),
    )
    assert_round_trip(parts, context)
    recognized = (scheme in OFFICIAL_SCHEMES) if scheme else None
    return type(url)._from_parts(parts, context, recognized_scheme=recognized)


def assert_round_trip(parts: URLParts, context: _URLContext) -> None:
    """Refuse derived parts whose string would name a different destination.

    A copy is assembled from components rather than parsed, so nothing
    else guarantees that ``str(url)`` goes where ``url`` reports -- and
    when it does not, the security checks validated one URL and the
    caller sends another. What decides the destination is the scheme and
    authority, plus the query not swallowing a "#". The path cannot move
    either (the builder escapes "?" and "#" in it, and a "//" path is only
    ever emitted after an authority or behind a "/." prefix), and the
    fragment comes last, so they are left out -- which also keeps a long
    percent-encoded path or fragment, longer serialized than the parse
    limits allow, from failing a derivation. Scheme-less URLs are skipped:
    they serialize without "//" by design (``build()``).
    """
    if parts.query is not None and "#" in parts.query:
        raise InvalidURLError("Derived URL does not round-trip: its query contains '#'.", component="query")
    if not parts.scheme:
        return
    authority_only = context.builder.compose(
        {"scheme": parts.scheme, "userinfo": parts.userinfo, "host": parts.host, "port": parts.port, "path": "/"}
    )
    try:
        reparsed = parse_components(authority_only, allow_custom_scheme=context.allow_custom_scheme)
    except InvalidURLError as exc:
        raise InvalidURLError(f"Derived URL does not re-parse: {exc.message}", component="url") from exc

    def effective_port(scheme: str | None, port: int | None) -> int | None:
        return port if port is not None else DEFAULT_PORTS.get((scheme or "").lower())

    comparisons = (
        ("scheme", parts.scheme, reparsed.scheme),
        ("userinfo", parts.userinfo, reparsed.userinfo),
        ("host", parts.host, reparsed.host),
        ("port", effective_port(parts.scheme, parts.port), effective_port(reparsed.scheme, reparsed.port)),
    )
    changed = [name for name, ours, theirs in comparisons if ours != theirs]
    if changed:
        raise InvalidURLError(
            f"Derived URL does not round-trip: re-parsing it would change {', '.join(changed)}.",
            component=changed[0],
        )


def _reconcile_query_components(components: dict[str, Any], overrides: Mapping[str, Any], builder: Builder) -> None:
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
    if overrode_query:
        query = components.get("query")
        components["query_pairs"] = builder.parse_query(query) if query else []
    else:
        pairs = components.get("query_pairs") or []
        components["query"] = builder.serialize_query(list(pairs)) if pairs else None


def netloc_overrides(netloc: str, scheme: str | None) -> dict[str, Any]:
    """The ``copy()`` overrides for ``with_netloc(netloc)``."""
    userinfo, host, port = parse_netloc(netloc, require_host=bool(netloc))
    if port is None and scheme and host:
        port = DEFAULT_PORTS.get(scheme.lower())
    return {"userinfo": userinfo, "host": host, "port": port}


__all__ = ["assert_round_trip", "derive", "netloc_overrides"]
