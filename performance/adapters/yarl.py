from __future__ import annotations

from typing import Any

from performance.adapters._registry import register_adapter
from performance.adapters._models import QueryResult, ComponentResult, capture_error, ParserAdapter
from performance.adapters._core import YARL_AVAILABLE, YARL_IMPORT_ERROR
from performance.adapters._utils import add_component


def yarl_components(parsed: Any) -> ComponentResult:
    """
    Extract components from yarl.URL.

    yarl exposes:

        scheme
        user
        password
        host
        port
        path
        query_string
        fragment

    It also exposes authority and other derived properties.

    yarl's `port` may contain scheme-derived defaults, so this adapter also
    exposes `explicit_port` where available.
    """

    result = ComponentResult()

    fields = [
        ("scheme", "scheme"),
        ("user", "user"),
        ("username", "user"),
        ("password", "password"),
        ("host", "host"),
        ("port", "port"),
        ("explicit_port", "explicit_port"),
        ("path", "path"),
        ("query", "query_string"),
        ("query_string", "query_string"),
        ("fragment", "fragment"),
        ("netloc", "authority"),
        ("authority", "authority"),
    ]

    for output_name, attribute_name in fields:
        add_component(
            result,
            output_name,
            parsed,
            attribute_name,
        )

    return result


def yarl_query(parsed: Any) -> QueryResult:
    """
    Use yarl's native query representation.

    yarl.URL.query returns a MultiDictProxy containing decoded query
    parameters.
    """

    try:
        query = getattr(parsed, "query")

        return QueryResult(
            value=query,
        )

    except Exception as exc:
        return QueryResult(
            error=capture_error("query", exc)
        )


def yarl_reconstruct(parsed: Any) -> str:
    return str(parsed)


def _create_yarl_adapter() -> ParserAdapter:
    if not YARL_AVAILABLE:
        reason = (
            "yarl is not installed"
            if YARL_IMPORT_ERROR is None
            else f"yarl import failed: {YARL_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="yarl",
            parse=lambda _: None,
            description="yarl.URL",
            available=False,
            unavailable_reason=reason,
        )

    from ._core import YarlURL

    return ParserAdapter(
        name="yarl",
        parse=YarlURL,
        component_extractor=yarl_components,
        query_extractor=yarl_query,
        reconstructor=yarl_reconstruct,
        description="yarl.URL",
    )


yarl_adapter = _create_yarl_adapter()
register_adapter(yarl_adapter)
