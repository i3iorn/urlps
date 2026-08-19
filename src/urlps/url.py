"""High-level immutable URL representation and manipulation.

This module provides the main URL class and helpers for parsing, building, and manipulating URLs.

Public API:
    - URL: Immutable URL object with rich methods for access and modification.
    - parse_relative_reference, build_relative_reference, round_trip_relative: Relative URL helpers.

Audit hooks are supplied per call via the ``audit=AuditConfig(...)`` parameter
rather than by module-level setters.

All public methods and properties are documented below.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._audit import NO_OP_AUDIT_MANAGER, AuditConfig, AuditManager
from ._builder import Builder, QueryPairs
from ._comparison import _URLComparison
from ._components import SecurityFinding
from ._helpers import _check_type, _normalize_port
from ._mutations import _URLMutations
from ._parser import Parser
from ._relative import build_relative_reference, parse_relative_reference, round_trip_relative
from ._security import (
    SecurityPolicy,
    extract_host_and_path,
    has_parser_confusion,
    has_path_traversal,
    is_open_redirect_risk,
)
from ._serialization import _URLSerialization
from ._validation import Validator, _URLValidation
from .constants import DEFAULT_PORTS, MAX_URL_LENGTH
from .exceptions import InvalidURLError, URLParseError


class URL:
    """Immutable URL representation.

    URLs are immutable by default. Use `copy()` or `with_*` methods to create modified versions.

    Args:
        url: The URL string to parse.
        parser: Optional custom parser instance.
        builder: Optional custom builder instance.
        debug: If True, include raw input in exception traces.
        check_dns: If True, perform DNS resolution checks.
        check_phishing: If True, check for known phishing domains.
        security_policy: Policy governing which checks are enforced. This is
            the single control for security behaviour. Defaults to ``strict``,
            matching :func:`urlps.parse_url` -- constructing ``URL(...)``
            directly must not be a quieter way to skip the checks that
            ``parse_url()`` applies. Pass ``SecurityPolicy.local()`` (or use
            :func:`urlps.parse_url_local`) for development URLs.
        correlation_id: Optional identifier propagated to audit events.
        audit: Optional AuditConfig supplying audit callbacks.

    Raises:
        URLParseError: If the URL is invalid or fails security checks.
    """

    __slots__ = (
        "_audit_manager",
        "_builder",
        "_check_dns",
        "_check_phishing",
        "_correlation_id",
        "_debug",
        "_fragment",
        "_frozen",
        "_host",
        "_parser",
        "_path",
        "_port",
        "_query",
        "_query_pairs",
        "_scheme",
        "_security_findings",
        "_security_policy",
        "_userinfo",
        "recognized_scheme",
    )

    def __setattr__(self, name: str, value: Any) -> None:
        """Block attribute assignment once construction has finished.

        A URL is validated exactly once, at construction. Without this guard a
        caller could do ``u._host = "evil.com"`` and walk straight past every
        check that ``parse_url()`` just ran -- the object would still report
        itself as validated while pointing somewhere else entirely. The four
        internal writers (``__init__``, ``copy``, ``_apply_parsed`` and
        unpickling) go through ``object.__setattr__`` deliberately.
        """
        if getattr(self, "_frozen", False):
            raise AttributeError(
                f"URL is immutable; use with_*() or copy() to derive a new URL (tried to set {name!r})"
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Block attribute deletion -- otherwise ``del u._host`` is a trivial bypass of __setattr__."""
        if getattr(self, "_frozen", False):
            raise AttributeError(
                f"URL is immutable; use with_*() or copy() to derive a new URL (tried to delete {name!r})"
            )
        object.__delattr__(self, name)

    def __init__(
        self,
        url: str,
        *,
        parser: Parser | None = None,
        builder: Builder | None = None,
        debug: bool = False,
        check_dns: bool = False,
        check_phishing: bool = False,
        security_policy: SecurityPolicy | None = None,
        correlation_id: str | None = None,
        audit: AuditConfig | None = None,
    ) -> None:
        # Must be first: __setattr__ consults it on every assignment below.
        object.__setattr__(self, "_frozen", False)

        _check_type(url, str, "url")
        _check_type(debug, bool, "debug")
        _check_type(check_dns, bool, "check_dns")
        _check_type(check_phishing, bool, "check_phishing")
        if audit is not None and not isinstance(audit, AuditConfig):
            raise TypeError(f"audit must be AuditConfig, got {type(audit).__name__}")

        self._parser = parser if parser is not None else Parser()
        self._builder = builder if builder is not None else Builder()
        self._audit_manager = AuditManager(audit) if audit is not None else NO_OP_AUDIT_MANAGER
        self._debug = debug
        self._check_dns = check_dns
        self._check_phishing = check_phishing
        self._security_policy = (
            security_policy if security_policy is not None else SecurityPolicy.strict(check_dns=check_dns)
        )
        self._security_findings: list[SecurityFinding] = []
        self._correlation_id = correlation_id
        self.recognized_scheme: bool | None = None

        self._parse_and_validate(url)
        object.__setattr__(self, "_frozen", True)

    def _parse_and_validate(self, url: str) -> None:
        """Parse URL and run security validations."""
        if not url.strip():
            raise URLParseError("A non-empty URL string is required.")
        if len(url) > MAX_URL_LENGTH:
            raise URLParseError("URL length exceeds maximum allowed size.")
        if not Validator.is_url_safe_string(url):
            raise URLParseError("URL contains invalid control characters.")

        try:
            if self._security_policy.enforce_parser_confusion and has_parser_confusion(url):
                _, pre_path = extract_host_and_path(url)
                if not (pre_path and (is_open_redirect_risk(pre_path) or has_path_traversal(pre_path))):
                    raise InvalidURLError("URL contains ambiguous syntax that could cause parser confusion.")
            parsed = self._parser.parse(url)
            self.recognized_scheme = self._parser.recognized_scheme
            self._apply_parsed(parsed)
            self._security_findings = self.validate(raise_on_error=True, raw_url=url)
            self._audit_manager.invoke(
                raw_url=url,
                parsed_url=self,
                exception=None,
                correlation_id=self._correlation_id,
            )
        except Exception as exc:
            self._audit_manager.invoke(raw_url=url, parsed_url=None, exception=exc, correlation_id=self._correlation_id)
            raise

    def _security_checks(self) -> None:
        """Run security validations on parsed URL."""
        self.validate(raise_on_error=True)

    def _apply_parsed(self, components: Mapping[str, Any | None]) -> None:
        """Apply parsed components to instance."""
        scheme_component = components.get("scheme")
        self._scheme = str(scheme_component) if scheme_component is not None else None
        userinfo_component = components.get("userinfo")
        self._userinfo = str(userinfo_component) if userinfo_component is not None else None
        host_component = components.get("host")
        self._host = str(host_component) if host_component is not None else None
        self._port: int | None = _normalize_port(components.get("port"))
        path_component = components.get("path")
        self._path = str(path_component) if path_component is not None else ""
        query_component = components.get("query")
        self._query = str(query_component) if query_component is not None else None
        fragment_component = components.get("fragment")
        self._fragment = str(fragment_component) if fragment_component is not None else None
        query_pairs = components.get("query_pairs")
        if isinstance(query_pairs, list):
            self._query_pairs = [(str(k), None if v is None else str(v)) for k, v in query_pairs]
        else:
            self._query_pairs = list(getattr(self._parser, "query_pairs", []))
        findings = components.get("security_findings")
        self._security_findings = list(findings) if isinstance(findings, list) else []

    @property
    def scheme(self) -> str | None:
        """The URL scheme (e.g., 'http', 'https')."""
        return self._scheme

    @property
    def host(self) -> str | None:
        """The host component (IDNA-encoded if applicable)."""
        return self._host

    @property
    def port(self) -> int | None:
        """The explicit port, or None if not present."""
        return self._port

    @property
    def userinfo(self) -> str | None:
        """The userinfo component (e.g., 'user:pass')."""
        return self._userinfo

    @property
    def path(self) -> str:
        """The path component (always a string, may be empty)."""
        return self._path

    @property
    def query(self) -> str | None:
        """The query string (without '?'), or None if not present."""
        return self._query

    @property
    def fragment(self) -> str | None:
        """The fragment string (without '#'), or None if not present."""
        return self._fragment

    @property
    def query_params(self) -> QueryPairs:
        """Return query parameters as list of (key, value) tuples."""
        return list(self._query_pairs)

    @property
    def query_pairs(self) -> QueryPairs:
        """Alias for query_params."""
        return self.query_params

    @property
    def netloc(self) -> str:
        """Return the network location (userinfo@host:port)."""
        return self._builder.build_netloc(self._userinfo, self._host, self._port, self._scheme)

    @property
    def effective_port(self) -> int | None:
        """Return explicit port or scheme default."""
        if self._port is not None:
            return self._port
        return DEFAULT_PORTS.get(self._scheme.lower()) if self._scheme else None

    @property
    def is_absolute(self) -> bool:
        """Check if URL is absolute (has scheme and host)."""
        return self.scheme is not None and self.host is not None

    @property
    def origin(self) -> str:
        """Return the origin (scheme://host:port) for same-origin comparisons.

        Raises:
            InvalidURLError: If the URL is not absolute.
        """
        if not self._scheme or not self._host:
            raise InvalidURLError("Cannot compute origin for relative URL.")
        port = self.effective_port
        if port and self._scheme and DEFAULT_PORTS.get(self._scheme.lower()) == port:
            port = None
        if port:
            return f"{self._scheme}://{self._host}:{port}"
        return f"{self._scheme}://{self._host}"

    def copy(self, **overrides: Any) -> URL:
        """Create a copy with optional component overrides.

        Args:
            overrides: Components to override (scheme, host, port, path, query, fragment, userinfo, query_pairs).
        Returns:
            A new URL instance with the specified overrides.
        Raises:
            InvalidURLError: If overrides are invalid.
        """
        return _URLMutations.copy(self, **overrides)

    def _reconcile_query_components(
        self,
        components: dict[str, Any],
        overrides: Mapping[str, Any],
    ) -> None:
        """Keep ``query`` and ``query_pairs`` from disagreeing after an override.

        They are two representations of one value. Overriding only one of them
        would otherwise leave the copy carrying the *previous* value in the
        other, so the stale one has to be re-derived from whichever the caller
        actually supplied.
        """
        _URLMutations._reconcile_query_components(components, overrides)

    def with_scheme(self, scheme: str | None) -> URL:
        """Return new URL with different scheme.

        `scheme=None` clears the scheme, consistent with every other `with_*`
        method (`with_host`, `with_query`, `with_fragment`, `with_userinfo`)
        accepting `None` to clear their component. Non-str, non-None values are
        still rejected -- `copy()`/`_validate_copy_overrides` already enforces
        that and validates the scheme format itself.
        """
        return _URLMutations.with_scheme(self, scheme)

    def with_host(self, host: str | None) -> URL:
        """Return new URL with different host."""
        return _URLMutations.with_host(self, host)

    def with_port(self, port: int | None) -> URL:
        """Return new URL with different port."""
        return _URLMutations.with_port(self, port)

    def with_path(self, path: str) -> URL:
        """Return new URL with different path."""
        return _URLMutations.with_path(self, path)

    def with_query(self, query: str | None) -> URL:
        """Return new URL with different query string."""
        return _URLMutations.with_query(self, query)

    def with_fragment(self, fragment: str | None) -> URL:
        """Return new URL with different fragment."""
        return _URLMutations.with_fragment(self, fragment)

    def with_userinfo(self, userinfo: str | None) -> URL:
        """Return new URL with different userinfo."""
        return _URLMutations.with_userinfo(self, userinfo)

    def with_netloc(self, netloc: str) -> URL:
        """Return new URL with different netloc (userinfo@host:port)."""
        return _URLMutations.with_netloc(self, netloc)

    def with_query_param(self, key: str, value: str | None = None) -> URL:
        """Return new URL with added query parameter."""
        return _URLMutations.with_query_param(self, key, value)

    def without_query_param(self, key: str) -> URL:
        """Return new URL with query parameter removed."""
        return _URLMutations.without_query_param(self, key)

    def without_query(self) -> URL:
        """Return new URL without query string or fragment."""
        return _URLMutations.without_query(self)

    def same_origin(self, other: URL) -> bool:
        """Check if this URL has the same origin as another URL."""
        return _URLMutations.same_origin(self, other)

    def canonicalize(self) -> URL:
        """Return a canonicalized copy of this URL (lowercase scheme/host, sorted query, normalized path)."""
        return _URLSerialization.canonicalize(self)

    def __copy__(self) -> URL:
        """Immutable, so a shallow copy can safely be the object itself."""
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> URL:
        """Immutable, so a deep copy can safely be the object itself.

        Defined explicitly because the default implementation reconstructs
        slot-by-slot through ``__setattr__``, which the immutability guard
        rejects.
        """
        memo[id(self)] = self
        return self

    #: Collaborators rather than URL data: a Parser/Builder is stateless
    #: machinery, and an AuditManager holds a thread lock and user callbacks
    #: (neither picklable, and a deserialized URL firing someone's audit
    #: callbacks would be surprising). They are rebuilt fresh on unpickle.
    _UNPICKLED_COLLABORATORS = ("_parser", "_builder", "_audit_manager")

    def __getstate__(self) -> dict[str, Any]:
        return {name: getattr(self, name, None) for name in URL.__slots__ if name not in URL._UNPICKLED_COLLABORATORS}

    def __setstate__(self, state: Mapping[str, Any]) -> None:
        """Restore via object.__setattr__ -- the default path trips the guard."""
        for name, value in state.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_parser", Parser())
        object.__setattr__(self, "_builder", Builder())
        object.__setattr__(self, "_audit_manager", NO_OP_AUDIT_MANAGER)
        object.__setattr__(self, "_frozen", True)

    def is_semantically_equal(self, other: URL) -> bool:
        """Check semantic equality after normalization."""
        return _URLComparison.is_semantically_equal(self, other)

    def as_string(self, *, mask_password: bool = False) -> str:
        """Return URL as string, optionally masking password in userinfo."""
        return _URLSerialization.as_string(self, mask_password=mask_password)

    @property
    def security_findings(self) -> list[SecurityFinding]:
        """Return the last computed security findings for this URL instance."""
        return list(self._security_findings)

    def validate(
        self,
        *,
        policy: SecurityPolicy | None = None,
        raise_on_error: bool = False,
        raw_url: str | None = None,
    ) -> list[SecurityFinding]:
        """Validate this URL against a security policy and return findings.

        Pure: the returned findings are *not* stored on the instance.
        ``security_findings`` reports what was found at construction, so
        ``validate(policy=stricter)`` can be used to ask a hypothetical
        question without rewriting the URL's own recorded verdict.
        """
        return _URLValidation.validate_security(self, policy=policy, raise_on_error=raise_on_error, raw_url=raw_url)

    def redacted(self) -> str:
        """Return a log-safe representation with sensitive values redacted."""
        return _URLSerialization.redacted(self)

    def _to_dict(self) -> dict[str, Any]:
        """Convert URL to dictionary of components."""
        return _URLSerialization.to_dict(self)

    def __str__(self) -> str:
        """Return the URL as a string."""
        return self.as_string()

    def __repr__(self) -> str:
        """Return a string representation of the URL object."""
        try:
            url = self.as_string()
        except InvalidURLError:
            url = "<invalid>"
        return f"URL('{url}')"

    def __hash__(self) -> int:
        """Return a hash of the URL object (for use in sets/dicts)."""
        return _URLComparison.hash_url(self)

    def __eq__(self, other: object) -> Any:
        """Check equality with another URL object."""
        return _URLComparison.equals(self, other)

    def __lt__(self, other: object) -> Any:
        """Compare URLs lexicographically for sorting."""
        return _URLComparison.compare_lt(self, other)

    def __le__(self, other: object) -> Any:
        """Compare URLs lexicographically for sorting."""
        return _URLComparison.compare_le(self, other)

    def __gt__(self, other: object) -> Any:
        """Compare URLs lexicographically for sorting."""
        return _URLComparison.compare_gt(self, other)

    def __ge__(self, other: object) -> Any:
        """Compare URLs lexicographically for sorting."""
        return _URLComparison.compare_ge(self, other)

    @classmethod
    def _validate_copy_overrides(cls, overrides: dict[str, Any]) -> None:
        """Validate copy() override arguments.

        Overrides are checked against the same component validators the parser
        uses. Previously this only verified that values were strings, so
        ``with_host("not a valid host!")`` succeeded and produced a URL object
        that ``parse_url`` would have rejected -- component validation on the
        mutation path was strictly weaker than on the parse path.
        """
        _URLValidation.validate_copy_overrides(overrides)

    @staticmethod
    def _is_valid_host_override(host: str) -> bool:
        """Return True if host is a valid hostname, IPv4 literal, or IPv6 literal."""
        return _URLValidation._is_valid_host_override(host)


# For backward compatibility with tests that import this private function
_validate_copy_overrides = _URLValidation.validate_copy_overrides

__all__ = [
    "URL",
    "build_relative_reference",
    "parse_relative_reference",
    "round_trip_relative",
]
