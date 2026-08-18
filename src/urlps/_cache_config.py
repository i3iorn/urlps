"""
Central sizing for every internal ``@lru_cache`` used across urlps.

``functools.lru_cache`` bakes ``maxsize`` in at decoration time, i.e. at
first import of the module that defines the decorated function -- it cannot
be changed once a process has started using urlps. To make these tunable
without a much larger rewrite (a custom cache with a runtime-resizable
``maxsize`` on every hot-path function), sizes are read from environment
variables once, here, before anything else in the package is imported.

**Set these before importing urlps** -- typically as real process
environment variables, or via ``os.environ`` at the very top of your
program, before ``import urlps`` runs for the first time:

    import os
    os.environ["URLPS_CACHE_SIZE_SECURITY"] = "8192"
    import urlps  # cache sizes are now locked in for this process

Setting them after import, or after the first ``parse_url()`` call, has no
effect.

See ``docs/caching.md`` for guidance on which value fits which workload; the
short version is that a cache only helps when you actually re-see the same
inputs (same host, same scheme+host+userinfo shape, ...) within the cache's
window, and hurts nobody when undersized -- it just falls back to doing the
work again, same as if there were no cache at all.
"""

from __future__ import annotations

import os


def _cache_size(env_var: str, default: int) -> int:
    raw = os.environ.get(env_var)
    if raw is None:
        return default

    try:
        value = int(raw)
    except ValueError:
        return default

    return value if value > 0 else default


# Security/host/URL-shape checks (is_ssrf_risk, is_private_ip,
# has_parser_confusion, has_mixed_scripts, find_authority_marker, ...).
# Keyed by host or full URL string -- size this to the number of distinct
# hosts/URLs you expect to see repeatedly within a process's lifetime.
SECURITY_CACHE_SIZE = _cache_size("URLPS_CACHE_SIZE_SECURITY", 512)

# Component-level validation predicates (is_valid_host, is_valid_scheme,
# is_url_safe_string, is_valid_fragment, ...).
VALIDATION_CACHE_SIZE = _cache_size("URLPS_CACHE_SIZE_VALIDATION", 512)

# Parser-level caches (normalize_path and similar).
PARSER_CACHE_SIZE = _cache_size("URLPS_CACHE_SIZE_PARSER", 1024)

# Builder-level percent-encoding caches. These key on short encoded
# fragments (a query key/value, a path segment) rather than whole URLs, so
# the natural working set is much smaller and the defaults are larger.
BUILDER_QUERY_ENCODE_CACHE_SIZE = _cache_size("URLPS_CACHE_SIZE_BUILDER_QUERY_ENCODE", 8192)
BUILDER_PATH_ENCODE_CACHE_SIZE = _cache_size("URLPS_CACHE_SIZE_BUILDER_PATH_ENCODE", 1024)

# Resolved named-policy cache (keyed on policy name + check_dns/check_phishing
# overrides -- there are only a handful of possible combinations, so this
# stays tiny regardless of workload).
POLICY_CACHE_SIZE = _cache_size("URLPS_CACHE_SIZE_POLICY", 16)
