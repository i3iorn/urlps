"""URL serialization and string conversion helpers.

Internal module: private helpers used by the URL class to maintain immutability
and separation of concerns. Not part of the public API.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .constants import DEFAULT_PORTS, PASSWORD_MASK

if TYPE_CHECKING:
    from .url import URL


class _URLSerialization:
    """String conversion, canonicalization, and serialization operations.

    All methods are static and accept a URL instance, maintaining separation
    of concerns without breaking immutability constraints.
    """

    __slots__ = ()

    @staticmethod
    def to_dict(url: URL) -> dict[str, Any]:
        """Convert URL to dictionary of components."""
        return {
            "scheme": url._scheme,
            "userinfo": url._userinfo,
            "host": url._host,
            "port": url._port,
            "path": url._path,
            "query": url._query,
            "fragment": url._fragment,
            "query_pairs": list(url._query_pairs),
        }

    @staticmethod
    def as_string(url: URL, *, mask_password: bool = False) -> str:
        """Return URL as string, optionally masking password in userinfo."""
        components = _URLSerialization.to_dict(url)
        if mask_password and components.get("userinfo"):
            userinfo = components["userinfo"]
            if ":" in userinfo:
                username, _, _ = userinfo.partition(":")
                components["userinfo"] = f"{username}:{PASSWORD_MASK}"
        return url._builder.compose(components)

    @staticmethod
    def canonicalize(url: URL) -> URL:
        """Return a canonicalized copy of this URL.

        Lowercases scheme/host, sorts query parameters, normalizes path.
        """
        canonical_scheme = url._scheme.lower() if url._scheme else None
        canonical_host = str(url._host).lower() if url._host else None
        canonical_port = url._port
        if canonical_scheme and canonical_port == DEFAULT_PORTS.get(canonical_scheme):
            canonical_port = None
        canonical_path = url._builder.normalize_path(url._path) if url._path else ""
        sorted_pairs = sorted(url._query_pairs, key=lambda x: (x[0], x[1] or ""))
        canonical_query = url._builder.serialize_query(sorted_pairs) if sorted_pairs else None

        # Pass query and query_pairs together rather than writing _query_pairs
        # afterwards: _reconcile_query_components treats "both supplied" as
        # "caller owns both" and keeps the sort order, which a post-hoc write
        # would otherwise have to smuggle past the immutability guard.
        return url.copy(
            scheme=canonical_scheme,
            host=canonical_host,
            port=canonical_port,
            path=canonical_path,
            query=canonical_query,
            query_pairs=sorted_pairs,
        )

    @staticmethod
    def redacted(url: URL) -> str:
        """Return a log-safe representation with sensitive values redacted."""
        from ._security import redact_url_for_logs

        return redact_url_for_logs(_URLSerialization.as_string(url))
