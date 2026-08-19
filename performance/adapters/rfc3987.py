from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs

from performance.adapters._core import RFC3987_AVAILABLE, RFC3987_IMPORT_ERROR
from performance.adapters._core import rfc3987_module as rfc3987
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


def rfc3987_components(parsed: Any) -> ComponentResult:
    """
    rfc3987.parse() already returns every component as a dict (scheme,
    authority, userinfo, host, port, path, query, fragment, plus the
    IPv4/IPv6/IPvFuture breakdown of the host) -- components extraction is
    just relaying that dict through add_component() for the safe-getattr
    error handling every other adapter gets, rather than a raw passthrough.
    """

    result = ComponentResult()

    fields = [
        "scheme",
        "authority",
        "userinfo",
        "host",
        "port",
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


def rfc3987_query(parsed: Any) -> QueryResult:
    try:
        query = parsed.get("query")

        return QueryResult(
            value={
                "raw": query,
                "params": parse_qs(
                    query or "",
                    keep_blank_values=True,
                ),
            }
        )

    except Exception as exc:
        return QueryResult(
            error=capture_error("query", exc)
        )


def rfc3987_reconstruct(parsed: Any) -> str:
    return rfc3987.compose(
        scheme=parsed.get("scheme"),
        authority=parsed.get("authority"),
        path=parsed.get("path"),
        query=parsed.get("query"),
        fragment=parsed.get("fragment"),
    )


def rfc3987_validate(url: str) -> bool:
    """
    `rfc3987.match()` is the library's own non-raising validity check --
    the same underlying regex `.parse()` uses internally, minus the group
    extraction/dict-building `.parse()` does on top once it matches.
    """
    return rfc3987.match(url, rule="URI") is not None


def rfc3987_modify_host(parsed: Any) -> str:
    """
    rfc3987.compose() only understands scheme/authority/path/query/fragment
    -- it has no host/port/userinfo parameters of its own (they're already
    folded into `authority` by parse()) -- so rebuild `authority` around
    MODIFIED_HOST, preserving whatever userinfo/port were already present,
    same as the rfc3986/uritools adapters' modify_host.
    """

    new_authority = MODIFIED_HOST

    if parsed.get("port"):
        new_authority = f"{new_authority}:{parsed['port']}"

    if parsed.get("userinfo"):
        new_authority = f"{parsed['userinfo']}@{new_authority}"

    return rfc3987.compose(
        scheme=parsed.get("scheme"),
        authority=new_authority,
        path=parsed.get("path"),
        query=parsed.get("query"),
        fragment=parsed.get("fragment"),
    )


def _create_rfc3987_adapter() -> ParserAdapter:
    if not RFC3987_AVAILABLE:
        reason = (
            "rfc3987 is not installed"
            if RFC3987_IMPORT_ERROR is None
            else f"rfc3987 import failed: {RFC3987_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="rfc3987",
            tags=frozenset({"parser", "rfc3986", "validation"}),
            parse=lambda _: None,
            description="rfc3987.parse",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="rfc3987",
        tags=frozenset({"parser", "rfc3986", "validation"}),
        parse=lambda url: rfc3987.parse(url, rule="URI"),
        component_extractor=rfc3987_components,
        query_extractor=rfc3987_query,
        reconstructor=rfc3987_reconstruct,
        path_modifier=lambda parsed: rfc3987.compose(
            scheme=parsed.get("scheme"),
            authority=parsed.get("authority"),
            path=MODIFIED_PATH,
            query=parsed.get("query"),
            fragment=parsed.get("fragment"),
        ),
        query_modifier=lambda parsed: rfc3987.compose(
            scheme=parsed.get("scheme"),
            authority=parsed.get("authority"),
            path=parsed.get("path"),
            query=MODIFIED_QUERY,
            fragment=parsed.get("fragment"),
        ),
        host_modifier=rfc3987_modify_host,
        fragment_modifier=lambda parsed: rfc3987.compose(
            scheme=parsed.get("scheme"),
            authority=parsed.get("authority"),
            path=parsed.get("path"),
            query=parsed.get("query"),
            fragment=MODIFIED_FRAGMENT,
        ),
        validator=rfc3987_validate,
        description="rfc3987.parse",
    )


rfc3987_adapter = _create_rfc3987_adapter()
register_adapter(rfc3987_adapter)
