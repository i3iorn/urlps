"""Relative URL reference parsing and building utilities."""
from __future__ import annotations

from typing import Dict, Optional
from .exceptions import InvalidURLError


def parse_relative_reference(reference: str) -> Dict[str, Optional[str]]:
    """Split a relative URL reference into path, query, and fragment."""
    if not isinstance(reference, str) or reference == "":
        raise InvalidURLError("Relative references must be non-empty strings.")
    if "://" in reference:
        raise InvalidURLError("Relative references cannot contain a scheme separator.")

    working = reference
    fragment: Optional[str] = None
    if "#" in working:
        working, _, fragment = working.partition("#")

    query: Optional[str] = None
    if "?" in working:
        path, _, query = working.partition("?")
    else:
        path = working

    return {"path": path, "query": query, "fragment": fragment}


def build_relative_reference(
    path: str,
    *,
    query: Optional[str] = None,
    fragment: Optional[str] = None
) -> str:
    """Compose a relative reference from raw path, query, and fragment."""
    if not isinstance(path, str):
        raise InvalidURLError("Relative path must be a string.")

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


__all__ = ["parse_relative_reference", "build_relative_reference", "round_trip_relative"]
