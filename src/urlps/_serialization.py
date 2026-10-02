"""URL serialization: components to string, and the canonical form.

Plain functions over :class:`~urlps._components.URLParts` and the builder
that spells them -- they need nothing else from a URL, so nothing here
depends on how ``URL`` stores its state.
"""

from __future__ import annotations

from typing import Any

from ._builder import Builder
from ._components import URLParts
from .constants import DEFAULT_PORTS, PASSWORD_MASK


def as_string(parts: URLParts, builder: Builder, *, mask_password: bool = False) -> str:
    """Serialize ``parts``, optionally masking the password in the userinfo."""
    components = parts.as_mapping()
    if mask_password and parts.userinfo and ":" in parts.userinfo:
        username, _, _ = parts.userinfo.partition(":")
        components["userinfo"] = f"{username}:{PASSWORD_MASK}"
    return builder.compose(components)


def canonical_overrides(parts: URLParts, builder: Builder) -> dict[str, Any]:
    """The ``copy()`` overrides that turn ``parts`` into its canonical form.

    Lowercased scheme and host, no explicit default port, normalized path,
    and query parameters sorted by key then value. ``query`` and
    ``query_pairs`` are passed together so the derivation keeps the sort
    order rather than re-deriving one from the other.
    """
    scheme = parts.scheme.lower() if parts.scheme else None
    port = parts.port
    if scheme and port == DEFAULT_PORTS.get(scheme):
        port = None
    sorted_pairs = sorted(parts.query_pairs, key=lambda pair: (pair[0], pair[1] or ""))
    return {
        "scheme": scheme,
        "host": parts.host.lower() if parts.host else None,
        "port": port,
        "path": builder.normalize_path(parts.path) if parts.path else "",
        "query": builder.serialize_query(sorted_pairs) if sorted_pairs else None,
        "query_pairs": sorted_pairs,
    }


__all__ = ["as_string", "canonical_overrides"]
