from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs

from performance.adapters._models import QueryResult, safe_call, ComponentResult, capture_error, ParserAdapter
from performance.adapters._core import RFC3986_AVAILABLE, RFC3986_IMPORT_ERROR, rfc3986_api
from performance.adapters._utils import add_component
from performance.adapters._registry import register_adapter


def rfc3986_components(parsed: Any) -> ComponentResult:
    """
    Extract components from an rfc3986 URIReference/ParseResult.

    rfc3986 exposes the core URI components:

        scheme
        authority
        path
        query
        fragment

    It additionally provides:

        userinfo
        host
        port

    through authority parsing.

    `authority_info()` can raise for malformed authorities, so it is
    deliberately isolated from the other component reads.
    """

    result = ComponentResult()

    fields = [
        ("scheme", "scheme"),
        ("authority", "authority"),
        ("path", "path"),
        ("query", "query"),
        ("fragment", "fragment"),
        ("userinfo", "userinfo"),
        ("host", "host"),
        ("port", "port"),
    ]

    # First extract the direct URI components.
    for output_name, attribute_name in fields[:5]:
        add_component(
            result,
            output_name,
            parsed,
            attribute_name,
        )

    # rfc3986's authority subcomponents are best obtained through
    # authority_info(). Do not allow one malformed authority to prevent
    # the rest of the result from being reported.
    authority_info, error = safe_call(
        lambda: parsed.authority_info(),
        stage="components.authority_info",
    )

    if error is not None:
        result.errors.append(error)

        # Preserve the common fields even when authority parsing failed.
        result.values.setdefault("userinfo", None)
        result.values.setdefault("host", None)
        result.values.setdefault("port", None)

        return result

    if authority_info is None:
        result.values["userinfo"] = None
        result.values["host"] = None
        result.values["port"] = None
        return result

    result.values["userinfo"] = authority_info.get("userinfo")
    result.values["host"] = authority_info.get("host")
    result.values["port"] = authority_info.get("port")

    return result


def rfc3986_query(parsed: Any) -> QueryResult:
    """
    Extract rfc3986's query component and additionally parse it into a
    standard-library-style mapping.

    The raw query is retained because rfc3986 itself models query as a URI
    component rather than as an application/x-www-form-urlencoded mapping.
    """

    try:
        query = getattr(parsed, "query")

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


def rfc3986_reconstruct(parsed: Any) -> str:
    return parsed.unsplit()


def _create_rfc3986_adapter() -> ParserAdapter:
    if not RFC3986_AVAILABLE:
        reason = (
            "rfc3986 is not installed"
            if RFC3986_IMPORT_ERROR is None
            else f"rfc3986 import failed: {RFC3986_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="rfc3986",
            parse=lambda _: None,
            description="rfc3986.api.uri_reference",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="rfc3986",
        parse=rfc3986_api.uri_reference,
        component_extractor=rfc3986_components,
        query_extractor=rfc3986_query,
        reconstructor=rfc3986_reconstruct,
        description="rfc3986.api.uri_reference",
    )


rfc3986_adapter = _create_rfc3986_adapter()
register_adapter(rfc3986_adapter)