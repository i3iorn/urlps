"""URL comparison and hashing helpers.

Internal module: handles equality, ordering, and hashing operations for URL objects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .url import URL


class _URLComparison:
    """URL comparison, ordering, and hashing operations."""

    __slots__ = ()

    @staticmethod
    def is_semantically_equal(url: URL, other: URL) -> bool:
        """Check semantic equality after normalization."""
        from ._serialization import _URLSerialization

        if not isinstance(other, type(url)):
            return False
        canonical_self = _URLSerialization.canonicalize(url).as_string()
        canonical_other = _URLSerialization.canonicalize(other).as_string()
        return canonical_self == canonical_other

    @staticmethod
    def hash_url(url: URL) -> int:
        """Return a hash of the URL object (for use in sets/dicts)."""
        return hash(
            (
                url._scheme,
                url._userinfo,
                url._host,
                url._port,
                url._path,
                url._query,
                url._fragment,
            )
        )

    @staticmethod
    def equals(url: URL, other: object) -> Any:
        """Check equality with another URL object."""
        from ._serialization import _URLSerialization

        if not isinstance(other, type(url)):
            return NotImplemented
        return _URLSerialization.as_string(url) == _URLSerialization.as_string(other)

    @staticmethod
    def compare_lt(url: URL, other: object) -> Any:
        """Compare URLs lexicographically for sorting."""
        from ._serialization import _URLSerialization

        if isinstance(other, type(url)):
            return _URLSerialization.as_string(url) < _URLSerialization.as_string(other)
        return NotImplemented

    @staticmethod
    def compare_le(url: URL, other: object) -> Any:
        """Compare URLs lexicographically for sorting."""
        from ._serialization import _URLSerialization

        if isinstance(other, type(url)):
            return _URLSerialization.as_string(url) <= _URLSerialization.as_string(other)
        return NotImplemented

    @staticmethod
    def compare_gt(url: URL, other: object) -> Any:
        """Compare URLs lexicographically for sorting."""
        from ._serialization import _URLSerialization

        if isinstance(other, type(url)):
            return _URLSerialization.as_string(url) > _URLSerialization.as_string(other)
        return NotImplemented

    @staticmethod
    def compare_ge(url: URL, other: object) -> Any:
        """Compare URLs lexicographically for sorting."""
        from ._serialization import _URLSerialization

        if isinstance(other, type(url)):
            return _URLSerialization.as_string(url) >= _URLSerialization.as_string(other)
        return NotImplemented
