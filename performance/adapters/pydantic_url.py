from __future__ import annotations

from typing import Any

from performance.adapters._core import PYDANTIC_AVAILABLE, PYDANTIC_IMPORT_ERROR
from performance.adapters._core import PydanticAnyUrl as PydanticUrl
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

# `AnyUrl(...)`/`HttpUrl(...)` both return the same underlying Rust
# `pydantic_core.Url` type regardless of which alias constructed it -- using
# AnyUrl as `parse` (rather than the stricter HttpUrl, which rejects
# non-http(s) schemes) keeps this adapter comparable against the general-
# purpose URL corpus the other adapters run against (ftp:/mailto:/data:
# URLs and the like), while still exercising the exact same component/
# build() API HttpUrl would.


def pydantic_components(parsed: Any) -> ComponentResult:
    result = ComponentResult()

    fields = [
        "scheme",
        "username",
        "password",
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


def pydantic_query(parsed: Any) -> QueryResult:
    try:
        return QueryResult(
            value=parsed.query_params(),
        )
    except Exception as exc:
        return QueryResult(
            error=capture_error("query", exc)
        )


def pydantic_reconstruct(parsed: Any) -> str:
    return str(parsed)


def pydantic_validate(url: str) -> bool:
    """
    pydantic has no separate "is this valid" check -- parsing *is* the
    validation (`AnyUrl(...)` raises `ValidationError` on anything it
    rejects), so this wires the same call as `parse` behind the `validate`
    operation. That still gives it a real entry in cross-adapter "validate"
    comparisons (the tag already claimed this capability) rather than
    silently having a "validation"-tagged adapter that never actually ran
    the `validate` operation.
    """
    return bool(PydanticUrl(url))


def _rebuild(parsed: Any, **overrides: Any) -> Any:
    """
    pydantic's Url is immutable with no per-instance "with_*"/copy_with --
    the only way to change one component is `.build()`, a classmethod that
    takes *every* component. Read the existing ones off `parsed` and layer
    the single override on top, exercising the same validation `.build()`
    does for a freshly-constructed URL rather than a cheaper internal path.
    """

    fields = {
        "scheme": parsed.scheme,
        "host": parsed.host,
        "username": parsed.username,
        "password": parsed.password,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
    }
    fields.update(overrides)

    return type(parsed).build(**fields)


def _create_pydantic_adapter() -> ParserAdapter:
    if not PYDANTIC_AVAILABLE:
        reason = (
            "pydantic is not installed"
            if PYDANTIC_IMPORT_ERROR is None
            else f"pydantic import failed: {PYDANTIC_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="pydantic",
            tags=frozenset({"parser", "validation"}),
            parse=lambda _: None,
            description="pydantic.AnyUrl (see also HttpUrl)",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="pydantic",
        tags=frozenset({"parser", "validation"}),
        parse=PydanticUrl,
        component_extractor=pydantic_components,
        query_extractor=pydantic_query,
        reconstructor=pydantic_reconstruct,
        path_modifier=lambda parsed: _rebuild(parsed, path=MODIFIED_PATH),
        query_modifier=lambda parsed: _rebuild(parsed, query=MODIFIED_QUERY),
        host_modifier=lambda parsed: _rebuild(parsed, host=MODIFIED_HOST),
        fragment_modifier=lambda parsed: _rebuild(parsed, fragment=MODIFIED_FRAGMENT),
        validator=pydantic_validate,
        description="pydantic.AnyUrl (see also HttpUrl)",
    )


pydantic_adapter = _create_pydantic_adapter()
register_adapter(pydantic_adapter)
