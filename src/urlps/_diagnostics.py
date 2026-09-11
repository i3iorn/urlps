"""Cache diagnostics aggregated across internal modules.

Lives on its own because it reaches into parser, validation, security, and
builder caches rather than belonging to any single one of them.
"""

from __future__ import annotations


def get_cache_info() -> dict:
    """Get statistics about all internal caches.

    Returns a dictionary with cache statistics for performance-critical functions:
    - Parser caches (path normalization)
    - Validation caches (scheme, host, IP validation)
    - Security caches (SSRF detection, mixed scripts)
    - Builder caches (percent encoding, query encoding)

    Returns:
        Dictionary mapping module names to their cache statistics.

    Example:
        >>> info = get_cache_info()
        >>> info['parser']['normalize_path']['hits']
        450
    """
    from . import _builder, _parser, _security, _validation

    return {
        "parser": _parser.get_cache_info(),
        "validation": _validation.Validator.get_cache_info(),
        "security": _security.get_cache_info(),
        "builder": {
            "percent_encode": _builder.Builder._percent_encode_cached.cache_info()._asdict()
            if hasattr(_builder.Builder._percent_encode_cached, "cache_info")
            else None,
            "encode_for_query": _builder._encode_for_query.cache_info()._asdict()
            if hasattr(_builder._encode_for_query, "cache_info")
            else None,
        },
    }


def clear_all_caches() -> dict:
    """Clear all internal caches and return previous sizes.

    This can be useful for:
    - Memory management in long-running applications
    - Testing to ensure fresh state
    - Resetting after processing a large batch of URLs

    Returns:
        Dictionary mapping module names to previous cache sizes.

    Example:
        >>> previous = clear_all_caches()
        >>> previous['parser']['normalize_path']
        127
    """
    from . import _builder, _parser, _security, _validation

    previous = {
        "parser": _parser.clear_caches(),
        "validation": _validation.Validator.clear_caches(),
        "security": _security.clear_caches(),
        "builder": {},
    }

    if hasattr(_builder.Builder._percent_encode_cached, "cache_clear"):
        previous["builder"]["percent_encode"] = _builder.Builder._percent_encode_cached.cache_info().currsize
        _builder.Builder._percent_encode_cached.cache_clear()

    if hasattr(_builder._encode_for_query, "cache_clear"):
        previous["builder"]["encode_for_query"] = _builder._encode_for_query.cache_info().currsize
        _builder._encode_for_query.cache_clear()

    return previous


__all__ = ["clear_all_caches", "get_cache_info"]
