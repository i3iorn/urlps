"""Relative URL reference parsing and building utilities.

For resolving a reference *against a base URI* (RFC 3986 Section 5), use
:func:`urlps.join`. These helpers only split and recompose a reference.
"""
from __future__ import annotations

from typing import Dict, Optional

from ._resolve import split_uri_reference
from .exceptions import RelativeReferenceError


def parse_relative_reference(reference: str) -> Dict[str, Optional[str]]:
    """Split a relative URL reference into path, query, and fragment.

    A reference is rejected only if it is genuinely absolute, i.e. it carries
    its own scheme. It previously rejected any reference containing ``://``
    anywhere, which wrongly refused ordinary relative references that embed a
    URL in a query value -- ``/redirect?next=http://example.com`` being the
    common case. That is the same substring-matching bug fixed in the scheme
    parser for 0.6.1, which had not been applied here.
    """
    if not isinstance(reference, str) or reference == "":
        raise RelativeReferenceError("Relative references must be non-empty strings.")

    parts = split_uri_reference(reference)
    if parts.scheme is not None:
        raise RelativeReferenceError(
            "Relative references cannot contain a scheme separator.",
            value=reference,
            component="scheme",
        )
    if parts.authority is not None:
        raise RelativeReferenceError(
            "Relative references cannot contain an authority component.",
            value=reference,
            component="authority",
        )

    return {"path": parts.path, "query": parts.query, "fragment": parts.fragment}


def build_relative_reference(
    path: str,
    *,
    query: Optional[str] = None,
    fragment: Optional[str] = None
) -> str:
    """Compose a relative reference from raw path, query, and fragment."""
    if not isinstance(path, str):
        raise RelativeReferenceError("Relative path must be a string.")

    reference = path
    if query is not None:
        reference += f"?{query}"
    if fragment is not None:
        reference += f"#{fragment}"
    return reference


def round_trip_relative(reference: str) -> str:
    """Return the same relative reference after a parse/compose round trip."""
    parts = parse_relative_reference(reference)
    path = parts["path"] if parts["path"] is not None else ""
    return build_relative_reference(path, query=parts["query"], fragment=parts["fragment"])


__all__ = ["build_relative_reference", "parse_relative_reference", "round_trip_relative"]
