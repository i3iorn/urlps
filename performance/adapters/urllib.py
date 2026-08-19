from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse, urlunparse

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


def urllib_components(parsed: Any) -> ComponentResult:
    """
    Extract urllib components safely.

    IMPORTANT:

    `parsed.port` is a property, not a plain field.

    For example:

        http://example.com:abc/

    urlparse() itself can succeed, but accessing `.port` raises:

        ValueError: Port could not be cast to integer value as 'abc'

    Every component is therefore retrieved independently.
    """

    result = ComponentResult()

    fields = [
        ("scheme", "scheme"),
        ("netloc", "netloc"),
        ("path", "path"),
        ("params", "params"),
        ("query", "query"),
        ("fragment", "fragment"),
        ("username", "username"),
        ("password", "password"),
        ("hostname", "hostname"),
        ("port", "port"),
    ]

    for output_name, attribute_name in fields:
        add_component(
            result,
            output_name,
            parsed,
            attribute_name,
        )

    return result


def urllib_query(parsed: Any) -> QueryResult:
    try:
        query = getattr(parsed, "query")

        return QueryResult(
            value=parse_qs(
                query,
                keep_blank_values=True,
            )
        )
    except Exception as exc:
        return QueryResult(
            error=capture_error("query", exc)
        )


def urllib_reconstruct(parsed: Any) -> str:
    return urlunparse(parsed)


def urllib_modify_host(parsed: Any) -> Any:
    """
    urllib's ParseResult has no standalone host field to `._replace()` --
    host lives inside `netloc`. Rebuild netloc around MODIFIED_HOST,
    preserving whatever userinfo/port were already present.
    """

    new_netloc = MODIFIED_HOST
    if parsed.port:
        new_netloc = f"{new_netloc}:{parsed.port}"

    userinfo = parsed.netloc.split("@", 1)[0] if "@" in parsed.netloc else None
    if userinfo:
        new_netloc = f"{userinfo}@{new_netloc}"

    return parsed._replace(netloc=new_netloc)


urllib_adapter = ParserAdapter(
    name="urllib",
    tags=frozenset({"parser", "rfc3986", "stdlib"}),
    parse=urlparse,
    component_extractor=urllib_components,
    query_extractor=urllib_query,
    reconstructor=urllib_reconstruct,
    path_modifier=lambda parsed: parsed._replace(path=MODIFIED_PATH),
    query_modifier=lambda parsed: parsed._replace(query=MODIFIED_QUERY),
    host_modifier=urllib_modify_host,
    fragment_modifier=lambda parsed: parsed._replace(fragment=MODIFIED_FRAGMENT),
    description="Python standard library urllib.parse.urlparse",
)

register_adapter(urllib_adapter)
