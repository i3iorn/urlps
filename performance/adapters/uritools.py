from __future__ import annotations

from typing import Any

from performance.adapters._core import URITOOLS_AVAILABLE, URITOOLS_IMPORT_ERROR
from performance.adapters._core import uritools as uritools_module
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


def uritools_components(parsed: Any) -> ComponentResult:
    """
    Extract components from a uritools SplitResult.

    uritools exposes the core URI components directly:

        scheme
        authority
        path
        query
        fragment

    and derives the following from `authority` itself (no separate
    parse-authority step needed, unlike rfc3986):

        userinfo
        host
        port
    """

    result = ComponentResult()

    fields = [
        "scheme",
        "authority",
        "path",
        "query",
        "fragment",
        "userinfo",
        "host",
        "port",
    ]

    for name in fields:
        add_component(
            result,
            name,
            parsed,
        )

    return result


def uritools_query(parsed: Any) -> QueryResult:
    """
    uritools's own query-to-mapping conversion (a defaultdict(list), so it
    preserves repeated keys like `parse_qs` does).
    """

    try:
        return QueryResult(
            value=parsed.getquerydict(),
        )

    except Exception as exc:
        return QueryResult(
            error=capture_error("query", exc)
        )


def uritools_reconstruct(parsed: Any) -> str:
    return parsed.geturi()


def uritools_validate(url: str) -> bool:
    """
    `urisplit()` (used as `parse`) never raises -- it's a lenient split that
    "succeeds" on any string, garbage included -- so `parse`'s own
    success/failure carries no validity signal for uritools. `isuri()` is
    the library's actual RFC 3986 conformance check, and is the only way to
    get that signal out of this adapter.
    """
    return uritools_module.isuri(url)


def uritools_modify_host(parsed: Any) -> Any:
    """
    uritools has no direct host component to `._replace()` -- host lives
    inside `authority`. Rebuild it around MODIFIED_HOST, preserving
    whatever userinfo/port were already present (both readable directly
    off `parsed`, unlike rfc3986 which needs a separate authority_info()
    call).
    """

    new_authority = MODIFIED_HOST

    if parsed.port:
        new_authority = f"{new_authority}:{parsed.port}"

    if parsed.userinfo:
        new_authority = f"{parsed.userinfo}@{new_authority}"

    return parsed._replace(authority=new_authority)


def _create_uritools_adapter() -> ParserAdapter:
    if not URITOOLS_AVAILABLE:
        reason = (
            "uritools is not installed"
            if URITOOLS_IMPORT_ERROR is None
            else f"uritools import failed: {URITOOLS_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="uritools",
            tags=frozenset({"parser", "rfc3986", "validation"}),
            parse=lambda _: None,
            description="uritools.urisplit",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="uritools",
        tags=frozenset({"parser", "rfc3986", "validation"}),
        parse=uritools_module.urisplit,
        component_extractor=uritools_components,
        query_extractor=uritools_query,
        reconstructor=uritools_reconstruct,
        path_modifier=lambda parsed: parsed._replace(path=MODIFIED_PATH),
        query_modifier=lambda parsed: parsed._replace(query=MODIFIED_QUERY),
        host_modifier=uritools_modify_host,
        fragment_modifier=lambda parsed: parsed._replace(fragment=MODIFIED_FRAGMENT),
        validator=uritools_validate,
        description="uritools.urisplit",
    )


uritools_adapter = _create_uritools_adapter()
register_adapter(uritools_adapter)
