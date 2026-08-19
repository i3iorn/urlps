from __future__ import annotations

from typing import Any

from performance.adapters._core import HYPERLINK_AVAILABLE, HYPERLINK_IMPORT_ERROR
from performance.adapters._core import hyperlink_parse as _hyperlink_parse
from performance.adapters._models import (
    MODIFIED_FRAGMENT,
    MODIFIED_HOST,
    MODIFIED_PATH,
    MODIFIED_QUERY,
    ComponentResult,
    ParserAdapter,
    QueryResult,
    capture_error,
)
from performance.adapters._registry import register_adapter
from performance.adapters._utils import add_component

# Hyperlink's `path`/`query` are structured tuples (decoded path segments;
# (key, value) pairs), not raw strings -- `.replace()` expects the same
# shape back, so the MODIFIED_* string constants need converting once up
# front rather than on every call.
_MODIFIED_PATH_SEGMENTS = tuple(MODIFIED_PATH.strip("/").split("/"))
_MODIFIED_QUERY_PAIRS = tuple(
    tuple(pair.split("=", 1)) for pair in MODIFIED_QUERY.split("&")
)


def hyperlink_components(parsed: Any) -> ComponentResult:
    """
    Extract components from a hyperlink DecodedURL.

    `path` and `query` are native structured forms (a tuple of decoded path
    segments; a tuple of (key, value) pairs) rather than strings -- that's
    Hyperlink's whole point (no manual join/split for callers) -- so they're
    exposed as-is rather than flattened to match the RFC-string-style
    adapters.
    """

    result = ComponentResult()

    fields = [
        "scheme",
        "host",
        "port",
        "path",
        "query",
        "fragment",
        "user",
        "userinfo",
    ]

    for name in fields:
        add_component(
            result,
            name,
            parsed,
            name,
        )

    return result


def hyperlink_query(parsed: Any) -> QueryResult:
    try:
        return QueryResult(
            value=parsed.query,
        )
    except Exception as exc:
        return QueryResult(
            error=capture_error("query", exc)
        )


def hyperlink_normalize(url: str) -> str:
    """
    Hyperlink's own `.normalize()` -- RFC 3986 syntax-based normalization
    (case folding, percent-encoding, dot-segment removal) plus its decoded
    view's own IRI-to-URI encoding -- distinct from `parse` + `reconstruct`,
    which round-trips without normalizing anything.
    """
    return str(_hyperlink_parse(url).normalize())


def hyperlink_reconstruct(parsed: Any) -> str:
    # DecodedURL.to_text()/to_uri() both deliberately omit the password
    # from their output (a security default -- avoids leaking credentials
    # into logs), so this adapter will not round-trip a URL's password.
    # That is Hyperlink's own choice, not a bug in this adapter.
    return parsed.to_text()


def _create_hyperlink_adapter() -> ParserAdapter:
    if not HYPERLINK_AVAILABLE:
        reason = (
            "hyperlink is not installed"
            if HYPERLINK_IMPORT_ERROR is None
            else f"hyperlink import failed: {HYPERLINK_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="hyperlink",
            tags=frozenset({"parser", "normalization"}),
            parse=lambda _: None,
            description="hyperlink.parse",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="hyperlink",
        tags=frozenset({"parser", "normalization"}),
        parse=_hyperlink_parse,
        component_extractor=hyperlink_components,
        query_extractor=hyperlink_query,
        reconstructor=hyperlink_reconstruct,
        path_modifier=lambda parsed: parsed.replace(path=_MODIFIED_PATH_SEGMENTS),
        query_modifier=lambda parsed: parsed.replace(query=_MODIFIED_QUERY_PAIRS),
        host_modifier=lambda parsed: parsed.replace(host=MODIFIED_HOST),
        fragment_modifier=lambda parsed: parsed.replace(fragment=MODIFIED_FRAGMENT),
        normalizer=hyperlink_normalize,
        description="hyperlink.parse",
    )


hyperlink_adapter = _create_hyperlink_adapter()
register_adapter(hyperlink_adapter)
