"""Cache diagnostics across the whole package.

Every cache registers itself with its group when it is defined (see
``_cache_config``), so these report and clear all of them -- including
caches added later -- without a list to keep in sync.
"""

from __future__ import annotations

from . import _cache_config

#: The groups get_cache_info() always reports, in this order.
_GROUPS = ("parser", "validation", "security", "builder")


def get_cache_info() -> dict:
    """Get statistics about all internal caches.

    Returns a dictionary with cache statistics for performance-critical functions:
    - Parser caches (path normalization)
    - Validation caches (scheme, host, IP validation)
    - Security caches (SSRF detection, mixed scripts)
    - Builder caches (percent encoding, query encoding)

    Returns:
        Dictionary mapping group names to {cache name: {hits, misses, maxsize, currsize}}.

    Example:
        >>> info = get_cache_info()
        >>> info['parser']['normalize_path']['hits']
        450
    """
    groups = dict.fromkeys(_GROUPS + _cache_config.cache_groups())
    return {group: _cache_config.cache_info(group) for group in groups}


def clear_all_caches() -> dict:
    """Clear all internal caches and return previous sizes.

    This can be useful for:
    - Memory management in long-running applications
    - Testing to ensure fresh state
    - Resetting after processing a large batch of URLs

    Returns:
        Dictionary mapping group names to {cache name: previous size}.

    Example:
        >>> previous = clear_all_caches()
        >>> previous['parser']['normalize_path']
        127
    """
    groups = dict.fromkeys(_GROUPS + _cache_config.cache_groups())
    return {group: _cache_config.clear_caches(group) for group in groups}


__all__ = ["clear_all_caches", "get_cache_info"]
