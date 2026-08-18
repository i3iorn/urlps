from __future__ import annotations

from typing import Any

from performance.adapters._registry import register_adapter
from src.urlps import get_cache_info, parse_url

from performance.adapters._utils import safe_getattr, add_component
from performance.adapters._models import QueryResult, ComponentResult, capture_error, ParserAdapter


def urlps_components(parsed: Any) -> ComponentResult:
    result = ComponentResult()

    fields = [
        "scheme",
        "host",
        "port",
        "path",
        "query",
        "fragment",
        "userinfo",
    ]

    for name in fields:
        add_component(
            result,
            name,
            parsed,
        )

    # netloc may or may not exist in urlps.
    value, error = safe_getattr(
        parsed,
        "netloc",
        stage="components.netloc",
    )

    result.values["netloc"] = value

    if error is not None:
        # netloc is optional in the adapter contract.
        if error.exception_type == "AttributeError":
            result.values["netloc"] = None
        else:
            result.errors.append(error)

    return result


def urlps_query(parsed: Any) -> QueryResult:
    try:
        # Prefer query_pairs because it exercises urlps's query handling.
        query_pairs = getattr(parsed, "query_params")

        return QueryResult(
            value=query_pairs,
        )

    except AttributeError:
        try:
            return QueryResult(
                value=getattr(parsed, "query")
            )

        except Exception as exc:
            return QueryResult(
                error=capture_error("query", exc)
            )

    except Exception as exc:
        return QueryResult(
            error=capture_error("query", exc)
        )


def urlps_reconstruct(parsed: Any) -> str:
    return str(parsed)


urlps_adapter = ParserAdapter(
    name="urlps",
    parse=parse_url,
    component_extractor=urlps_components,
    query_extractor=urlps_query,
    reconstructor=urlps_reconstruct,
    description="urlps.parse_url",
    cache_info=get_cache_info,
)
register_adapter(urlps_adapter)
