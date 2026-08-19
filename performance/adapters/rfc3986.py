from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs

from performance.adapters._core import (
    RFC3986_AVAILABLE,
    RFC3986_IMPORT_ERROR,
    rfc3986_api,
    rfc3986_exceptions,
    rfc3986_validators,
)
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
from performance.adapters._utils import add_component


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


def rfc3986_validate(url: str) -> bool:
    """
    Plain `uri_reference()` (used as `parse`) never raises -- it's a lenient
    split, not a validator, so it always "succeeds" even on garbage input.
    rfc3986's own `Validator` is the library's actual is-this-valid check:
    it requires a scheme and host and confirms every component matches its
    RFC 3986 grammar, raising `ValidationError` if not.
    """
    validator = (
        rfc3986_validators.Validator()
        .require_presence_of("scheme", "host")
        .check_validity_of("scheme", "host", "path", "query", "fragment")
    )

    try:
        validator.validate(rfc3986_api.uri_reference(url))
        return True
    except rfc3986_exceptions.ValidationError:
        return False


def rfc3986_normalize(url: str) -> str:
    """rfc3986's own RFC 3986 §6 syntax-based normalization (case folding, percent-encoding, dot-segment removal)."""
    return rfc3986_api.uri_reference(url).normalize().unsplit()


def rfc3986_modify_host(parsed: Any) -> Any:
    """
    rfc3986 has no direct host component -- host is a substring of
    `authority`. Rebuild the authority around MODIFIED_HOST, preserving
    whatever userinfo/port were already present.
    """

    authority_info = parsed.authority_info() or {}

    userinfo = authority_info.get("userinfo")
    port = authority_info.get("port")

    new_authority = MODIFIED_HOST
    if port:
        new_authority = f"{new_authority}:{port}"
    if userinfo:
        new_authority = f"{userinfo}@{new_authority}"

    return parsed.copy_with(authority=new_authority)


def _create_rfc3986_adapter() -> ParserAdapter:
    if not RFC3986_AVAILABLE:
        reason = (
            "rfc3986 is not installed"
            if RFC3986_IMPORT_ERROR is None
            else f"rfc3986 import failed: {RFC3986_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="rfc3986",
            tags=frozenset({"parser", "rfc3986", "validation", "normalization"}),
            parse=lambda _: None,
            description="rfc3986.api.uri_reference",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="rfc3986",
        tags=frozenset({"parser", "rfc3986", "validation", "normalization"}),
        parse=rfc3986_api.uri_reference,
        component_extractor=rfc3986_components,
        query_extractor=rfc3986_query,
        reconstructor=rfc3986_reconstruct,
        path_modifier=lambda parsed: parsed.copy_with(path=MODIFIED_PATH),
        query_modifier=lambda parsed: parsed.copy_with(query=MODIFIED_QUERY),
        host_modifier=rfc3986_modify_host,
        fragment_modifier=lambda parsed: parsed.copy_with(fragment=MODIFIED_FRAGMENT),
        validator=rfc3986_validate,
        normalizer=rfc3986_normalize,
        description="rfc3986.api.uri_reference",
    )


rfc3986_adapter = _create_rfc3986_adapter()
register_adapter(rfc3986_adapter)