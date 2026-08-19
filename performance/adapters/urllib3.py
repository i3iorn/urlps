from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs

from performance.adapters._core import URLLIB3_AVAILABLE, URLLIB3_IMPORT_ERROR, urllib3_parse_url
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
from performance.adapters._utils import add_component, split_userinfo


def urllib3_components(parsed: Any) -> ComponentResult:
    """
    Extract components from urllib3.util.Url.

    urllib3's URL object exposes:

        scheme
        auth
        host
        port
        path
        query
        fragment

    It also provides convenience properties such as:

        authority
        hostname
        netloc

    Note: `auth_decoded`/`auth_decoded_joined` do not exist on urllib3's Url
    object (checked against urllib3 2.x) despite older docs suggesting
    otherwise; `auth` is a raw "user:pass" string, split below instead.
    """

    result = ComponentResult()

    fields = [
        ("scheme", "scheme"),
        ("auth", "auth"),
        ("host", "host"),
        ("port", "port"),
        ("path", "path"),
        ("query", "query"),
        ("fragment", "fragment"),
        ("authority", "authority"),
        ("netloc", "netloc"),
        ("hostname", "hostname"),
    ]

    for output_name, attribute_name in fields:
        add_component(
            result,
            output_name,
            parsed,
            attribute_name,
        )

    username, password = split_userinfo(result.values.get("auth"))
    result.values["username"] = username
    result.values["password"] = password

    return result


def urllib3_query(parsed: Any) -> QueryResult:
    """
    urllib3 exposes query as a raw string.

    Convert it to a parse_qs representation while preserving the raw query.
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


def urllib3_reconstruct(parsed: Any) -> str:
    return parsed.url


def _create_urllib3_adapter() -> ParserAdapter:
    if not URLLIB3_AVAILABLE:
        reason = (
            "urllib3 is not installed"
            if URLLIB3_IMPORT_ERROR is None
            else f"urllib3 import failed: {URLLIB3_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="urllib3",
            tags=frozenset({"parser", "rfc3986"}),
            parse=lambda _: None,
            description="urllib3.util.parse_url",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="urllib3",
        tags=frozenset({"parser", "rfc3986"}),
        parse=urllib3_parse_url,
        component_extractor=urllib3_components,
        query_extractor=urllib3_query,
        reconstructor=urllib3_reconstruct,
        # urllib3.util.url.Url is a NamedTuple; "modification" is `._replace()`.
        path_modifier=lambda parsed: parsed._replace(path=MODIFIED_PATH),
        query_modifier=lambda parsed: parsed._replace(query=MODIFIED_QUERY),
        host_modifier=lambda parsed: parsed._replace(host=MODIFIED_HOST),
        fragment_modifier=lambda parsed: parsed._replace(fragment=MODIFIED_FRAGMENT),
        description="urllib3.util.parse_url",
    )


urllib3_adapter = _create_urllib3_adapter()
register_adapter(urllib3_adapter)
