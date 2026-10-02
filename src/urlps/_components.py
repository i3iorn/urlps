"""
URL component dataclasses.

Immutable, auditable, security‑first structures for URL parsing and manipulation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

QueryPairs = list[tuple[str, str | None]]


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    """Structured security finding emitted by URL validation.

    Attributes:
        severity: One of ``"critical"``, ``"major"`` or ``"warning"``.
            ``critical`` and ``major`` block (see ``BLOCKING_SEVERITIES``);
            ``warning`` is advisory and never raises.
        code: Machine‑readable identifier for the finding.
        message: Human‑readable description of the issue.
        component: Optional URL component associated with the finding.
        remediation: Optional human-readable next step, e.g. which policy or
            entry point to use if the rejection was not what the caller
            wanted. Carried as its own field rather than concatenated into
            ``message`` so structured consumers keep the two separable.
    """

    severity: str
    code: str
    message: str
    component: str | None = None
    remediation: str | None = None
    #: For a retryable finding (DNS rate limiting), seconds until a retry can succeed.
    retry_after: float | None = None


@dataclass(frozen=True, slots=True)
class ParseResult:
    """Immutable result of parsing a URL string.

    Attributes:
        scheme: URL scheme (e.g., "https").
        userinfo: User information section.
        host: Hostname or IP literal.
        port: Port number if present.
        path: URL path component.
        query: Raw query string.
        fragment: Fragment identifier.
        query_pairs: Parsed query key/value pairs.
        recognized_scheme: Whether the scheme is recognized by the parser.
        security_findings: List of security findings discovered during parsing.
    """

    scheme: str | None = None
    userinfo: str | None = None
    host: str | None = None
    port: int | None = None
    path: str = ""
    query: str | None = None
    fragment: str | None = None
    query_pairs: QueryPairs = field(default_factory=list)
    recognized_scheme: bool | None = None
    security_findings: list[SecurityFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a dictionary representation of the URL components."""
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


__all__ = [
    "ParseResult",
    "QueryPairs",
    "SecurityFinding",
]
