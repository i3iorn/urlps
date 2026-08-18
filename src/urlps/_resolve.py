"""RFC 3986 Section 5 reference resolution.

Implements the algorithm for resolving a URI reference against a base URI:

* ``remove_dot_segments`` -- Section 5.2.4
* ``merge_paths``         -- Section 5.2.3
* ``transform_reference`` -- Section 5.2.2
* ``recompose``           -- Section 5.3

The RFC distinguishes an *undefined* component from an *empty* one, and the
distinction is load-bearing: ``http://a`` (undefined path) and ``http://a/``
(empty-then-root path) resolve references differently, and a reference of
``""`` inherits the base query while ``"?"`` clears it. ``None`` means
undefined and ``""`` means empty throughout this module.
"""

from __future__ import annotations

import re
from typing import NamedTuple

# RFC 3986 Appendix B: the reference implementation's parsing regex. Using the
# RFC's own expression keeps the undefined/empty distinction that a hand-rolled
# splitter tends to lose.
_URI_REFERENCE_RE = re.compile(
    r"^(?:([^:/?#]+):)?"  # scheme
    r"(?://([^/?#]*))?"  # authority
    r"([^?#]*)"  # path (always defined, possibly empty)
    r"(?:\?([^#]*))?"  # query
    r"(?:#(.*))?$",  # fragment
    re.DOTALL,
)


class UriParts(NamedTuple):
    """The five generic URI components. ``None`` means undefined."""

    scheme: str | None
    authority: str | None
    path: str
    query: str | None
    fragment: str | None


def split_uri_reference(reference: str) -> UriParts:
    """Split a URI reference into its five components (RFC 3986 Appendix B)."""
    if not isinstance(reference, str):
        raise TypeError(f"reference must be str, got {type(reference).__name__}")

    match = _URI_REFERENCE_RE.match(reference)
    if match is None:  # pragma: no cover - the regex matches any string
        raise ValueError(f"Could not parse URI reference: {reference!r}")

    scheme, authority, path, query, fragment = match.groups()
    return UriParts(scheme, authority, path or "", query, fragment)


def remove_dot_segments(path: str) -> str:
    """Resolve ``.`` and ``..`` segments in a path (RFC 3986 Section 5.2.4).

    Implemented as the RFC's literal loop rather than a split/join shortcut,
    because the edge cases (a trailing ``/.``, a ``..`` that would escape the
    root, a bare ``..``) are exactly where shortcuts diverge from the spec.

    Note that ``..`` can never escape above the root: excess ``..`` segments
    are discarded, which is what makes this safe to apply to attacker-supplied
    references.
    """
    input_buffer = path
    output_segments: list[str] = []

    while input_buffer:
        # A. Leading "../" or "./" -- drop it.
        if input_buffer.startswith("../"):
            input_buffer = input_buffer[3:]
            continue
        if input_buffer.startswith("./"):
            input_buffer = input_buffer[2:]
            continue

        # B. Leading "/./" or a trailing "/." -- replace with "/".
        if input_buffer.startswith("/./"):
            input_buffer = "/" + input_buffer[3:]
            continue
        if input_buffer == "/.":
            input_buffer = "/"
            continue

        # C. Leading "/../" or a trailing "/.." -- replace with "/" and pop.
        if input_buffer.startswith("/../"):
            input_buffer = "/" + input_buffer[4:]
            if output_segments:
                output_segments.pop()
            continue
        if input_buffer == "/..":
            input_buffer = "/"
            if output_segments:
                output_segments.pop()
            continue

        # D. A lone "." or ".." -- drop it.
        if input_buffer in (".", ".."):
            input_buffer = ""
            continue

        # E. Move the first path segment to the output buffer.
        if input_buffer.startswith("/"):
            next_slash = input_buffer.find("/", 1)
        else:
            next_slash = input_buffer.find("/")

        if next_slash == -1:
            output_segments.append(input_buffer)
            input_buffer = ""
        else:
            output_segments.append(input_buffer[:next_slash])
            input_buffer = input_buffer[next_slash:]

    return "".join(output_segments)


def merge_paths(base_authority: str | None, base_path: str, reference_path: str) -> str:
    """Merge a relative reference path onto a base path (RFC 3986 Section 5.2.3)."""
    if base_authority is not None and base_path == "":
        return "/" + reference_path

    # All but the last segment of the base path.
    last_slash = base_path.rfind("/")
    if last_slash == -1:
        return reference_path
    return base_path[: last_slash + 1] + reference_path


def transform_reference(base: UriParts, reference: UriParts, *, strict: bool = True) -> UriParts:
    """Resolve a reference against a base (RFC 3986 Section 5.2.2).

    Args:
        base: The base URI. Must be absolute (its scheme must be defined).
        reference: The reference to resolve.
        strict: When False, a reference whose scheme equals the base scheme is
            treated as if the scheme were undefined. This is the RFC 5.2.2
            backwards-compatibility behaviour for older parsers that emitted
            ``http:relative`` forms. Defaults to True (strict), which is what
            modern parsers do.

    Returns:
        The resolved components, ready for :func:`recompose`.
    """
    ref_scheme = reference.scheme
    if not strict and ref_scheme is not None and ref_scheme == base.scheme:
        ref_scheme = None

    if ref_scheme is not None:
        return UriParts(
            scheme=ref_scheme,
            authority=reference.authority,
            path=remove_dot_segments(reference.path),
            query=reference.query,
            fragment=reference.fragment,
        )

    if reference.authority is not None:
        return UriParts(
            scheme=base.scheme,
            authority=reference.authority,
            path=remove_dot_segments(reference.path),
            query=reference.query,
            fragment=reference.fragment,
        )

    if reference.path == "":
        # An empty reference path keeps the base path, and inherits the base
        # query only when the reference does not supply one of its own. This
        # is why "" and "?" resolve differently.
        return UriParts(
            scheme=base.scheme,
            authority=base.authority,
            path=base.path,
            query=reference.query if reference.query is not None else base.query,
            fragment=reference.fragment,
        )

    if reference.path.startswith("/"):
        resolved_path = remove_dot_segments(reference.path)
    else:
        resolved_path = remove_dot_segments(merge_paths(base.authority, base.path, reference.path))

    return UriParts(
        scheme=base.scheme,
        authority=base.authority,
        path=resolved_path,
        query=reference.query,
        fragment=reference.fragment,
    )


def recompose(parts: UriParts) -> str:
    """Recompose components into a URI string (RFC 3986 Section 5.3)."""
    result = ""
    if parts.scheme is not None:
        result += f"{parts.scheme}:"
    if parts.authority is not None:
        result += f"//{parts.authority}"
    result += parts.path
    if parts.query is not None:
        result += f"?{parts.query}"
    if parts.fragment is not None:
        result += f"#{parts.fragment}"
    return result


def resolve_reference(base: str, reference: str, *, strict: bool = True) -> str:
    """Resolve ``reference`` against ``base`` and return the target URI string.

    This is the pure string-level algorithm. The public :func:`urlps.join`
    wraps it so the result is also parsed and security-validated.

    Raises:
        ValueError: If ``base`` is not an absolute URI (RFC 3986 requires the
            base to have a scheme).
    """
    base_parts = split_uri_reference(base)
    if base_parts.scheme is None:
        raise ValueError(f"Base URI must be absolute (have a scheme); got {base!r}")

    reference_parts = split_uri_reference(reference)
    target = transform_reference(base_parts, reference_parts, strict=strict)
    return recompose(target)


__all__ = [
    "UriParts",
    "merge_paths",
    "recompose",
    "remove_dot_segments",
    "resolve_reference",
    "split_uri_reference",
    "transform_reference",
]
