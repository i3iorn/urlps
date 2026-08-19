"""
URL component dataclasses.

Immutable, auditable, security‑first structures for URL parsing and manipulation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

QueryPairs = list[tuple[str, str | None]]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class URLComponentError(Exception):
    """Raised when invalid URL component data is provided."""


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


@dataclass(frozen=True, slots=True)
class URLComponents:
    """Immutable URL components for construction or manipulation.

    Attributes mirror ParseResult but are intended for building URLs.
    """

    scheme: str | None = None
    userinfo: str | None = None
    host: str | None = None
    port: int | None = None
    path: str = ""
    query: str | None = None
    fragment: str | None = None
    query_pairs: QueryPairs = field(default_factory=list)

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def with_updates(self, **updates: Any) -> URLComponents:
        """Return a new URLComponents with validated updates applied.

        Raises:
            URLComponentError: If an update contains invalid data.
        """
        # Constructed field-by-field rather than via **dict so each argument
        # keeps its own type; a dict of mixed value types erases them.
        return URLComponents(
            scheme=self._validated_str(updates.get("scheme", self.scheme)),
            userinfo=self._validated_str(updates.get("userinfo", self.userinfo)),
            host=self._validated_str(updates.get("host", self.host)),
            port=self._validated_port(updates.get("port", self.port)),
            path=self._validated_str(updates.get("path", self.path), allow_empty=True) or "",
            query=self._validated_str(updates.get("query", self.query)),
            fragment=self._validated_str(updates.get("fragment", self.fragment)),
            query_pairs=self._validated_query_pairs(updates.get("query_pairs", self.query_pairs)),
        )

    # -----------------------------------------------------------------------
    # Validation Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _validated_str(value: Any, allow_empty: bool = False) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise URLComponentError("Expected string or None for text fields.")
        if not allow_empty and value == "":
            raise URLComponentError("Empty string not allowed for this field.")
        return value

    @staticmethod
    def _validated_port(value: Any) -> int | None:
        if value is None:
            return None
        if isinstance(value, int) and 0 < value <= 65535:
            return value
        raise URLComponentError("Port must be an integer in range 1–65535.")

    @staticmethod
    def _validated_query_pairs(value: Any) -> QueryPairs:
        if not isinstance(value, list):
            raise URLComponentError("query_pairs must be a list of (key, value) tuples.")
        validated_pairs: QueryPairs = []
        for pair in value:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or not isinstance(pair[0], str)
                or (pair[1] is not None and not isinstance(pair[1], str))
            ):
                raise URLComponentError("Invalid query pair structure.")
            validated_pairs.append(pair)
        return validated_pairs


__all__ = [
    "ParseResult",
    "QueryPairs",
    "SecurityFinding",
    "URLComponentError",
    "URLComponents",
]
