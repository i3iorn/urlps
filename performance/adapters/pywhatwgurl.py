from __future__ import annotations

from typing import Any

from performance.adapters._core import PYWHATWGURL_AVAILABLE, PYWHATWGURL_IMPORT_ERROR, WhatwgURL
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


def pywhatwgurl_components(parsed: Any) -> ComponentResult:
    """
    Extract components from a pywhatwgurl.URL.

    pywhatwgurl mirrors the browser/JS `URL` object rather than RFC 3986
    naming, so it exposes:

        protocol (scheme, with trailing ":")
        username / password
        host (hostname:port) / hostname / port
        pathname
        search (query, with leading "?") / hash (fragment, with leading "#")
        origin / href

    RFC-style aliases (scheme/path/query/fragment) are also captured
    alongside the native names so this adapter's output stays comparable
    with the RFC-3986-flavored adapters (rfc3986, uritools, urllib3, ...).
    """

    result = ComponentResult()

    fields = [
        ("protocol", "protocol"),
        ("scheme", "protocol"),
        ("username", "username"),
        ("password", "password"),
        ("host", "host"),
        ("hostname", "hostname"),
        ("port", "port"),
        ("pathname", "pathname"),
        ("path", "pathname"),
        ("search", "search"),
        ("query", "search"),
        ("hash", "hash"),
        ("fragment", "hash"),
        ("origin", "origin"),
        ("href", "href"),
    ]

    for output_name, attribute_name in fields:
        add_component(
            result,
            output_name,
            parsed,
            attribute_name,
        )

    return result


def pywhatwgurl_query(parsed: Any) -> QueryResult:
    """
    Use pywhatwgurl's native URLSearchParams -- a browser-style multi-value
    mapping (`.get`/`.get_all`/`.items`), so repeated keys survive rather
    than being collapsed the way a plain dict would.
    """

    try:
        return QueryResult(
            value=parsed.search_params,
        )

    except Exception as exc:
        return QueryResult(
            error=capture_error("query", exc)
        )


def pywhatwgurl_reconstruct(parsed: Any) -> str:
    return str(parsed)


def pywhatwgurl_normalize(url: str) -> str:
    """
    The WHATWG URL parsing algorithm *is* a normalization step by spec
    design (lowercases scheme/host, percent-encodes, resolves dot-segments,
    drops default ports, ...) -- unlike `reconstruct`, which serializes an
    already-parsed object, this runs parse+serialize as one step directly
    from the raw string, the same shape as a dedicated normalize-only
    library (url-normalize) rather than two separately-timed operations.
    """
    return str(WhatwgURL(url))


def _copy(parsed: Any) -> Any:
    """
    pywhatwgurl.URL mutates in place (its `with_*` equivalents are plain
    property setters), so every modifier re-parses from `href` first to
    avoid corrupting the object other operations in the same benchmark run
    still use -- same reason furl's modifiers copy() first.
    """
    return WhatwgURL(parsed.href)


def pywhatwgurl_modify_path(parsed: Any) -> Any:
    copy = _copy(parsed)
    copy.pathname = MODIFIED_PATH
    return copy


def pywhatwgurl_modify_query(parsed: Any) -> Any:
    copy = _copy(parsed)
    copy.search = MODIFIED_QUERY
    return copy


def pywhatwgurl_modify_host(parsed: Any) -> Any:
    copy = _copy(parsed)
    copy.hostname = MODIFIED_HOST
    return copy


def pywhatwgurl_modify_fragment(parsed: Any) -> Any:
    copy = _copy(parsed)
    copy.hash = MODIFIED_FRAGMENT
    return copy


def _create_pywhatwgurl_adapter() -> ParserAdapter:
    if not PYWHATWGURL_AVAILABLE:
        reason = (
            "pywhatwgurl is not installed"
            if PYWHATWGURL_IMPORT_ERROR is None
            else f"pywhatwgurl import failed: {PYWHATWGURL_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="pywhatwgurl",
            tags=frozenset({"parser", "whatwg", "normalization"}),
            parse=lambda _: None,
            description="pywhatwgurl.URL",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="pywhatwgurl",
        tags=frozenset({"parser", "whatwg", "normalization"}),
        parse=WhatwgURL,
        component_extractor=pywhatwgurl_components,
        query_extractor=pywhatwgurl_query,
        reconstructor=pywhatwgurl_reconstruct,
        path_modifier=pywhatwgurl_modify_path,
        query_modifier=pywhatwgurl_modify_query,
        host_modifier=pywhatwgurl_modify_host,
        fragment_modifier=pywhatwgurl_modify_fragment,
        normalizer=pywhatwgurl_normalize,
        description="pywhatwgurl.URL",
    )


pywhatwgurl_adapter = _create_pywhatwgurl_adapter()
register_adapter(pywhatwgurl_adapter)
