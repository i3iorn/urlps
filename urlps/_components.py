"""URL component dataclasses.

This module defines immutable dataclasses for URL components,
used throughout the library for structured data passing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple
import sys

QueryPairs = List[Tuple[str, Optional[str]]]

_SUPPORTS_SLOTS = sys.version_info >= (3, 10)


@dataclass(frozen=True, slots=_SUPPORTS_SLOTS)
class SecurityFinding:
    """Structured finding emitted by URL security validation."""

    severity: str
    code: str
    message: str
    component: Optional[str] = None


@dataclass(frozen=True, slots=_SUPPORTS_SLOTS)
class ParseResult:
    """Result of parsing a URL string.

    This immutable dataclass contains all components extracted from a URL,
    making the parser stateless and thread-safe.

    Performance: Uses __slots__ on Python 3.10+ for reduced memory footprint.
    """
    scheme: Optional[str] = None
    userinfo: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    path: str = ""
    query: Optional[str] = None
    fragment: Optional[str] = None
    query_pairs: QueryPairs = field(default_factory=list)
    recognized_scheme: Optional[bool] = None
    security_findings: List[SecurityFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary of URL components."""
        return {
            "scheme": self.scheme,
            "userinfo": self.userinfo,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
            "security_findings": list(self.security_findings),
        }


@dataclass(frozen=True, slots=_SUPPORTS_SLOTS)
class URLComponents:
    """Components of a URL for building or manipulation.

    Unlike ParseResult, this can be used for constructing URLs
    with all components optional.

    Performance: Uses __slots__ on Python 3.10+ for reduced memory footprint.
    """
    scheme: Optional[str] = None
    userinfo: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    path: str = ""
    query: Optional[str] = None
    fragment: Optional[str] = None
    query_pairs: QueryPairs = field(default_factory=list)

    def with_updates(self, **kwargs: Any) -> 'URLComponents':
        """Create a new URLComponents with specified fields updated."""
        scheme = kwargs.get("scheme", self.scheme)
        userinfo = kwargs.get("userinfo", self.userinfo)
        host = kwargs.get("host", self.host)
        port_val = kwargs.get("port", self.port)
        port = int(port_val) if port_val is not None else None
        path = kwargs.get("path", self.path)
        query = kwargs.get("query", self.query)
        fragment = kwargs.get("fragment", self.fragment)
        query_pairs = kwargs.get("query_pairs", self.query_pairs)
        return URLComponents(
            scheme=scheme,
            userinfo=userinfo,
            host=host,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            query_pairs=query_pairs,
        )


__all__ = ["ParseResult", "URLComponents", "QueryPairs", "SecurityFinding"]
