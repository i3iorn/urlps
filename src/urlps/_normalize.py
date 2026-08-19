"""
RFC 3986 §6.2.2 syntax-based normalization.

These run unconditionally on every parse *and* build path. Normalizing rather
than rejecting is deliberate: a URL that differs only in host case, a trailing
root dot, or percent-encoding spelling denotes the *same* resource, so
rejecting it is user-hostile, while leaving it un-normalized is a security
problem -- a caller's ``url.host in ALLOWLIST`` check silently fails to match
``EXAMPLE.COM`` or ``evil.com.``.

This module deliberately has no intra-package dependencies beyond the cache
sizing constants, so both :mod:`urlps._parser` and :mod:`urlps._builder` can
import it without an import cycle.
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

from ._cache_config import PARSER_CACHE_SIZE

#: The unreserved set (RFC 3986 §2.3). These are the *only* characters that
#: may be percent-decoded during normalization. They are never delimiters, so
#: decoding them cannot change how the URL parses.
#:
#: Decoding anything outside this set is a vulnerability, not an optimization:
#: turning ``%2F`` into ``/`` invents a new path segment (the classic
#: traversal-via-normalization bug), and the same applies to ``%3F``, ``%23``,
#: ``%26``, ``%3D``, ``%40`` and ``%3A``. This is an allowlist for exactly
#: that reason -- never rewrite it as "decode unless denied".
UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")


def _normalize_escape(match: re.Match[str]) -> str:
    """Decode an unreserved escape; otherwise upper-case its hex digits."""
    hex_digits = match.group(1)
    char = chr(int(hex_digits, 16))
    if char in UNRESERVED:
        return char
    return f"%{hex_digits.upper()}"


@lru_cache(maxsize=PARSER_CACHE_SIZE)
def normalize_percent_encoding(value: str) -> str:
    """
    Apply RFC 3986 §6.2.2.1-.2 to a single URL component.

    - §6.2.2.1 -- percent-encoding hex digits are upper-cased (``%2f`` -> ``%2F``).
    - §6.2.2.2 -- escapes of unreserved characters are decoded (``%7E`` -> ``~``).

    Both are provably semantics-preserving. Everything else is left byte-exact:
    reserved-character escapes keep their meaning, and the caller's path case,
    query key/value case and parameter order are never touched (signature
    schemes such as AWS SigV4 and webhook HMACs depend on them surviving
    intact).
    """
    if "%" not in value:
        return value
    return _PERCENT_ESCAPE.sub(_normalize_escape, value)


@lru_cache(maxsize=PARSER_CACHE_SIZE)
def normalize_host(host: str) -> str:
    """
    Canonicalize a host so that equal hosts compare equal.

    - ASCII case-folds the host (DNS is case-insensitive).
    - Strips one trailing root dot (``evil.com.`` and ``evil.com`` resolve
      identically, so they must not compare differently).
    - Canonicalizes bracketed IPv6 literals via :mod:`ipaddress`, preserving
      any ``%zone`` suffix byte-exact so zone-ID inspection still sees the
      original text.

    Applied on every parse *and* build path, so it must be idempotent.
    """
    if not host:
        return host

    if host.startswith("[") and host.endswith("]"):
        inner = host[1:-1]
        address, sep, zone = inner.partition("%")
        try:
            parsed = ipaddress.IPv6Address(address)
        except ValueError:
            # Not a parseable literal -- validation elsewhere reports it; do
            # not mask that here by rewriting the text.
            return host.lower()
        # RFC 5952 §5: IPv4-mapped addresses keep the dotted-quad tail.
        # ipaddress.compressed does not implement that rule and would render
        # ::ffff:127.0.0.1 as ::ffff:7f00:1, which is the same address but
        # unrecognizable to a human reading a log or an allowlist.
        mapped = parsed.ipv4_mapped
        canonical = f"::ffff:{mapped}" if mapped is not None else parsed.compressed
        return f"[{canonical}{sep}{zone}]"

    host = host.lower()
    if len(host) > 1 and host.endswith("."):
        host = host[:-1]
    return host
