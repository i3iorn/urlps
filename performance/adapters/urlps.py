from __future__ import annotations

from typing import Any

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
from performance.adapters._utils import add_component, safe_getattr
from src.urlps import get_cache_info, parse_url


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


def url_validate(parsed: Any) -> Any:
    url = parse_url(parsed)
    findings = url.validate()
    return len(findings) == 0

def url_normalize(parsed: Any) -> Any:
    url = parse_url(parsed)
    return url.canonicalize().as_string()

urlps_adapter = ParserAdapter(
    name="urlps",
    tags=frozenset({"parser", "rfc3986", "validation", "security", "normalization"}),
    parse=parse_url,
    component_extractor=urlps_components,
    query_extractor=urlps_query,
    reconstructor=urlps_reconstruct,
    path_modifier=lambda parsed: parsed.with_path(MODIFIED_PATH),
    query_modifier=lambda parsed: parsed.with_query(MODIFIED_QUERY),
    host_modifier=lambda parsed: parsed.with_host(MODIFIED_HOST),
    fragment_modifier=lambda parsed: parsed.with_fragment(MODIFIED_FRAGMENT),
    validator=url_validate,
    normalizer=url_normalize,
    description="urlps.parse_url",
    cache_info=get_cache_info,
)
register_adapter(urlps_adapter)
