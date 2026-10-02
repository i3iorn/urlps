"""URL derivation: ``copy()`` and the ``with_*()`` methods.

Works on :class:`~urlps._components.URLParts` and the URL's context; a new
URL is built through ``type(url)._from_parts`` -- the same constructor path
every derived URL takes -- so this module never imports ``URL`` itself.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from ._helpers import _normalize_port
from ._parser import normalize_components, parse_netloc
from ._parser import parse_url as parse_components
from ._validation import _URLValidation
from .constants import DEFAULT_PORTS, OFFICIAL_SCHEMES
from .exceptions import InvalidURLError

if TYPE_CHECKING:
    from ._components import URLParts
    from .url import URL, _URLContext


def derive(url: URL, overrides: Mapping[str, Any]) -> URL:
    """Return a new URL: ``url`` with ``overrides`` applied, validated under its own policy.

    Every component -- overridden or carried over -- goes through
    :func:`normalize_components`, the same rules ``parse_url`` applies after
    splitting a string, so a derived URL is exactly what parsing its own
    string would give: ``with_path("/a/../b").path`` is ``"/b"``, and
    ``with_port(None)`` on an https URL leaves the default port 443, just as
    ``parse_url("https://h/")`` does.
    """
    context = url._context
    _URLValidation.validate_copy_overrides(dict(overrides), allow_custom_scheme=context.allow_custom_scheme)
    current = url._parts

    def value(name: str) -> Any:
        return overrides[name] if name in overrides else getattr(current, name)

    scheme = value("scheme")
    if isinstance(scheme, str):
        scheme = scheme.lower()
    port = _normalize_port(overrides["port"]) if "port" in overrides else current.port
    if "scheme" in overrides and "port" not in overrides:
        # The old scheme's default port is not an explicit choice; carrying
        # it over turned https://h/ into http://h:443/.
        if current.port is not None and current.port == DEFAULT_PORTS.get((current.scheme or "").lower()):
            port = None
    # ``query`` and ``query_pairs`` are two views of one value. The query
    # string is authoritative; pairs alone are serialized into one.
    if "query" in overrides:
        query = overrides["query"]
    elif "query_pairs" in overrides:
        query = context.builder.serialize_query(list(overrides["query_pairs"] or ())) or None
    else:
        query = current.query

    parts = normalize_components(
        scheme=scheme,
        userinfo=value("userinfo"),
        host=value("host"),
        port=port,
        path=value("path") or "",
        query=query,
        fragment=value("fragment"),
        require_host=bool(scheme) and scheme != "file",
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


def netloc_overrides(netloc: str, scheme: str | None) -> dict[str, Any]:
    """The ``copy()`` overrides for ``with_netloc(netloc)``."""
    userinfo, host, port = parse_netloc(netloc, require_host=bool(netloc))
    if port is None and scheme and host:
        port = DEFAULT_PORTS.get(scheme.lower())
    return {"userinfo": userinfo, "host": host, "port": port}


__all__ = ["assert_round_trip", "derive", "netloc_overrides"]
