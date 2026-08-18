from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlunparse, urlparse

from performance.adapters._models import QueryResult, ComponentResult, capture_error, ParserAdapter
from performance.adapters._utils import add_component

from performance.adapters._registry import register_adapter


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


urllib_adapter = ParserAdapter(
    name="urllib",
    parse=urlparse,
    component_extractor=urllib_components,
    query_extractor=urllib_query,
    reconstructor=urllib_reconstruct,
    description="Python standard library urllib.parse.urlparse",
)

register_adapter(urllib_adapter)
