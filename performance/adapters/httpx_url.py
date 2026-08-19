from __future__ import annotations

from typing import Any

from performance.adapters._core import HTTPX_AVAILABLE, HTTPX_IMPORT_ERROR, HttpxURL
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


def httpx_components(parsed: Any) -> ComponentResult:
    result = ComponentResult()

    fields = [
        "scheme",
        "username",
        "password",
        "host",
        "port",
        "netloc",
        "path",
        "query",
        "fragment",
    ]

    for name in fields:
        add_component(
            result,
            name,
            parsed,
            name,
        )

    return result


def httpx_query(parsed: Any) -> QueryResult:
    """httpx's own QueryParams -- a multi-value mapping, native to httpx."""

    try:
        return QueryResult(
            value=parsed.params,
        )
    except Exception as exc:
        return QueryResult(
            error=capture_error("query", exc)
        )


def httpx_reconstruct(parsed: Any) -> str:
    return str(parsed)


def _create_httpx_adapter() -> ParserAdapter:
    if not HTTPX_AVAILABLE:
        reason = (
            "httpx is not installed"
            if HTTPX_IMPORT_ERROR is None
            else f"httpx import failed: {HTTPX_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="httpx",
            tags=frozenset({"parser", "http-client"}),
            parse=lambda _: None,
            description="httpx.URL",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="httpx",
        tags=frozenset({"parser", "http-client"}),
        parse=HttpxURL,
        component_extractor=httpx_components,
        query_extractor=httpx_query,
        reconstructor=httpx_reconstruct,
        path_modifier=lambda parsed: parsed.copy_with(path=MODIFIED_PATH),
        query_modifier=lambda parsed: parsed.copy_with(query=MODIFIED_QUERY.encode()),
        host_modifier=lambda parsed: parsed.copy_with(host=MODIFIED_HOST),
        fragment_modifier=lambda parsed: parsed.copy_with(fragment=MODIFIED_FRAGMENT),
        description="httpx.URL",
    )


httpx_adapter = _create_httpx_adapter()
register_adapter(httpx_adapter)
