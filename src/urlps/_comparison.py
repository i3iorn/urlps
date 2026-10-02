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
        """Return a hash of the URL object (for use in sets/dicts).

        Hashes exactly what ``equals`` compares -- the serialized string. A
        hash over the raw components broke ``a == b -> hash(a) == hash(b)``:
        ``https://h/`` with port 443 and with port None serialize identically
        but hashed apart, so a set kept both. It also makes a URL and its
        string hash alike, consistent with ``url == str(url)``.
        """
        from ._serialization import _URLSerialization

        return hash(_URLSerialization.as_string(url))

    @staticmethod
    def equals(url: URL, other: object) -> Any:
        """Check equality with another URL object, or with a plain string.

        Comparing to a string compares against ``as_string()`` byte-for-byte
        (no canonicalization) -- the same "compare what was actually parsed"
        contract ``as_string()`` itself documents.
        """
        from ._serialization import _URLSerialization

        if isinstance(other, type(url)):
            return _URLSerialization.as_string(url) == _URLSerialization.as_string(other)
        if isinstance(other, str):
            return _URLSerialization.as_string(url) == other
        return NotImplemented

    @staticmethod
    def compare_lt(url: URL, other: object) -> Any:
        """Compare URLs (or a URL and a string) lexicographically for sorting."""
        from ._serialization import _URLSerialization

        if isinstance(other, type(url)):
            return _URLSerialization.as_string(url) < _URLSerialization.as_string(other)
        if isinstance(other, str):
            return _URLSerialization.as_string(url) < other
        return NotImplemented

    @staticmethod
    def compare_le(url: URL, other: object) -> Any:
        """Compare URLs (or a URL and a string) lexicographically for sorting."""
        from ._serialization import _URLSerialization

        if isinstance(other, type(url)):
            return _URLSerialization.as_string(url) <= _URLSerialization.as_string(other)
        if isinstance(other, str):
            return _URLSerialization.as_string(url) <= other
        return NotImplemented

    @staticmethod
    def compare_gt(url: URL, other: object) -> Any:
        """Compare URLs (or a URL and a string) lexicographically for sorting."""
        from ._serialization import _URLSerialization

        if isinstance(other, type(url)):
            return _URLSerialization.as_string(url) > _URLSerialization.as_string(other)
        if isinstance(other, str):
            return _URLSerialization.as_string(url) > other
        return NotImplemented

    @staticmethod
    def compare_ge(url: URL, other: object) -> Any:
        """Compare URLs (or a URL and a string) lexicographically for sorting."""
        from ._serialization import _URLSerialization

        if isinstance(other, type(url)):
            return _URLSerialization.as_string(url) >= _URLSerialization.as_string(other)
        if isinstance(other, str):
            return _URLSerialization.as_string(url) >= other
        return NotImplemented
