from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs

from performance.adapters._models import ComponentResult, capture_error, OperationError


def safe_getattr(
    obj: Any,
    name: str,
    *,
    stage: str,
) -> tuple[Any, OperationError | None]:
    """
    Safely retrieve an attribute.

    This is essential for urllib.parse because properties such as `.port`
    can raise ValueError lazily even after urlparse() itself succeeded.

    It is also useful for third-party URL objects where accessing a property
    can trigger validation or decoding.
    """

    try:
        return getattr(obj, name), None
    except Exception as exc:
        return None, capture_error(stage, exc)


def add_component(
    result: ComponentResult,
    output_name: str,
    obj: Any,
    attribute_name: str | None = None,
) -> None:
    """
    Retrieve a component and append any error to the ComponentResult.
    """

    attribute_name = attribute_name or output_name

    value, error = safe_getattr(
        obj,
        attribute_name,
        stage=f"components.{output_name}",
    )

    result.values[output_name] = value

    if error is not None:
        result.errors.append(error)


def split_userinfo(userinfo: Any) -> tuple[Any, Any]:
    """
    Split RFC-style userinfo into username/password.

    Examples:

        "user"          -> ("user", None)
        "user:password" -> ("user", "password")
        None            -> (None, None)

    This intentionally does not unquote the values. The rfc3986 parser
    exposes URI components rather than necessarily providing the same
    decoded semantics as urllib/yarl/furl.
    """

    if userinfo is None:
        return None, None

    if not isinstance(userinfo, str):
        userinfo = str(userinfo)

    if ":" in userinfo:
        username, password = userinfo.split(":", 1)
        return username, password

    return userinfo, None


def normalize_query_mapping(query: Any) -> Any:
    """
    Convert a query-like object into something reasonably comparable.

    The benchmark deliberately does not require every parser to return the
    exact same query container type.
    """

    if query is None:
        return {}

    if isinstance(query, str):
        return parse_qs(
            query,
            keep_blank_values=True,
        )

    return query
