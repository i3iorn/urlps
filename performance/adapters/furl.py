from __future__ import annotations

from typing import Any

from performance.adapters._core import FURL_AVAILABLE, FURL_IMPORT_ERROR, Furl
from performance.adapters._models import (
    MODIFIED_FRAGMENT,
    MODIFIED_HOST,
    MODIFIED_PATH,
    MODIFIED_QUERY,
    ComponentResult,
    ParserAdapter,
    QueryResult,
    capture_error,
    safe_call,
)
from performance.adapters._registry import register_adapter
from performance.adapters._utils import add_component, safe_getattr


def furl_components(parsed: Any) -> ComponentResult:
    """
    Extract components from a furl.furl object.

    furl exposes:

        scheme
        username
        password
        host
        port
        netloc
        path
        query
        fragment
        url

    `path`, `query`, and `fragment` are richer furl objects, so this adapter
    exposes both their object representation and useful string forms.
    """

    result = ComponentResult()

    fields = [
        ("scheme", "scheme"),
        ("username", "username"),
        ("password", "password"),
        ("host", "host"),
        ("port", "port"),
        ("netloc", "netloc"),
        ("origin", "origin"),
        ("path", "path"),
        ("query", "query"),
        ("fragment", "fragment"),
        ("url", "url"),
    ]

    for output_name, attribute_name in fields:
        add_component(
            result,
            output_name,
            parsed,
            attribute_name,
        )

    # Provide explicit string versions for the richer furl objects.
    path, path_error = safe_getattr(
        parsed,
        "path",
        stage="components.path_string",
    )

    if path_error is None:
        value, error = safe_call(
            lambda: str(path),
            stage="components.path_string",
        )
        result.values["path_string"] = value

        if error is not None:
            result.errors.append(error)
    else:
        result.values["path_string"] = None
        result.errors.append(path_error)

    query, query_error = safe_getattr(
        parsed,
        "query",
        stage="components.query_string",
    )

    if query_error is None:
        value, error = safe_call(
            lambda: str(query),
            stage="components.query_string",
        )
        result.values["query_string"] = value

        if error is not None:
            result.errors.append(error)
    else:
        result.values["query_string"] = None
        result.errors.append(query_error)

    fragment, fragment_error = safe_getattr(
        parsed,
        "fragment",
        stage="components.fragment_string",
    )

    if fragment_error is None:
        value, error = safe_call(
            lambda: str(fragment),
            stage="components.fragment_string",
        )
        result.values["fragment_string"] = value

        if error is not None:
            result.errors.append(error)
    else:
        result.values["fragment_string"] = None
        result.errors.append(fragment_error)

    return result


def furl_query(parsed: Any) -> QueryResult:
    """
    Extract furl's native query parameters.

    furl exposes query parameters through:

        parsed.query.params
        parsed.args

    The native representation is returned rather than converting it to a
    normal dict, because furl supports ordered/multivalue parameters.
    """

    try:
        query = getattr(parsed, "query")
        params = getattr(query, "params")

        return QueryResult(
            value=params,
        )

    except Exception as exc:
        return QueryResult(
            error=capture_error("query", exc)
        )


def furl_reconstruct(parsed: Any) -> str:
    return parsed.url


def _create_furl_adapter() -> ParserAdapter:
    if not FURL_AVAILABLE:
        reason = (
            "furl is not installed"
            if FURL_IMPORT_ERROR is None
            else f"furl import failed: {FURL_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="furl",
            tags=frozenset({"parser", "rfc3986"}),
            parse=lambda _: None,
            description="furl.furl",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="furl",
        tags=frozenset({"parser", "rfc3986"}),
        parse=Furl,
        component_extractor=furl_components,
        query_extractor=furl_query,
        reconstructor=furl_reconstruct,
        # furl mutates in place, so copy() first to avoid corrupting the
        # object other operations in the same benchmark run still use.
        path_modifier=lambda parsed: parsed.copy().set(path=MODIFIED_PATH),
        query_modifier=lambda parsed: parsed.copy().set(query=MODIFIED_QUERY),
        host_modifier=lambda parsed: parsed.copy().set(host=MODIFIED_HOST),
        fragment_modifier=lambda parsed: parsed.copy().set(fragment=MODIFIED_FRAGMENT),
        description="furl.furl",
    )


furl_adapter = _create_furl_adapter()
register_adapter(furl_adapter)
