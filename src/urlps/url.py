"""High-level immutable URL representation and manipulation.

This module provides the main URL class and helpers for parsing, building, and manipulating URLs.

Public API:
    - URL: Immutable URL object with rich methods for access and modification.
    - set_audit_callback, get_audit_callback: Audit hooks for URL parsing events.
    - parse_relative_reference, build_relative_reference, round_trip_relative: Relative URL helpers.

All public methods and properties are documented below.
"""
from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Type, cast

from ._security import SecurityPolicy, has_parser_confusion, extract_host_and_path, is_open_redirect_risk, \
    has_path_traversal, redact_url_for_logs, validate_url_security
from ._builder import Builder, QueryPairs
from ._audit import AuditConfig, AuditEventCallback, AuditCallback, AuditManager
from ._relative import parse_relative_reference, build_relative_reference, round_trip_relative
from .constants import DEFAULT_PORTS, MAX_URL_LENGTH, PASSWORD_MASK
from .exceptions import InvalidURLError, URLParseError
from ._parser import Parser
from ._components import SecurityFinding
from ._validation import Validator, is_valid_userinfo


def _check_type(value: Any, expected: Type, name: str) -> None:
    """Validate that value is of expected type."""
    if not isinstance(value, expected):
        raise TypeError(f"{name} must be {expected.__name__}, got {type(value).__name__}")


class URL:
    """Immutable URL representation.

    URLs are immutable by default. Use `copy()` or `with_*` methods to create modified versions.

    Args:
        url: The URL string to parse.
        parser: Optional custom parser instance.
        builder: Optional custom builder instance.
        strict: If True, enable SSRF and security checks.
        debug: If True, include raw input in exception traces.
        check_dns: If True, perform DNS resolution checks.
        check_phishing: If True, check for known phishing domains.

    Raises:
        URLParseError: If the URL is invalid or fails security checks.
    """

    __slots__ = (
        'recognized_scheme', '_parser', '_builder', '_strict', '_debug',
        '_check_dns', '_scheme', '_userinfo', '_host', '_port', '_path',
        '_query', '_fragment', '_query_pairs', '_check_phishing',
        '_security_policy', '_security_findings', '_correlation_id', '_audit_manager'
    )

    def __init__(
        self, url: str, *,
        parser: Optional[Parser] = None,
        builder: Optional[Builder] = None,
        strict: bool = False,
        debug: bool = False,
        check_dns: bool = False,
        check_phishing: bool = False,
        security_policy: Optional[SecurityPolicy] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        _check_type(url, str, "url")
        _check_type(strict, bool, "strict")
        _check_type(debug, bool, "debug")
        _check_type(check_dns, bool, "check_dns")
        _check_type(check_phishing, bool, "check_phishing")

        self._parser = parser if parser is not None else Parser()
        self._builder = builder if builder is not None else Builder()
        self._audit_manager = AuditManager()
        self._strict = strict
        self._debug = debug
        self._check_dns = check_dns
        self._check_phishing = check_phishing
        self._security_policy = (
            security_policy
            if security_policy is not None
            else SecurityPolicy.internal(check_dns=check_dns, enforce_ssrf=strict)
        )
        self._security_findings: List[SecurityFinding] = []
        self._correlation_id = correlation_id
        self.recognized_scheme: Optional[bool] = None

        self._parse_and_validate(url)

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
                if not (
                    pre_path
                    and (
                        is_open_redirect_risk(pre_path)
                        or has_path_traversal(pre_path)
                    )
                ):
                    raise InvalidURLError(
                        "URL contains ambiguous syntax that could cause parser confusion."
                    )
            parsed = self._parser.parse(url)
            self.recognized_scheme = self._parser.recognized_scheme
            self._apply_parsed(parsed)
            self.validate(raise_on_error=True, raw_url=url)
            self._audit_manager.invoke(
                raw_url=url,
                parsed_url=self,
                exception=None,
                correlation_id=self._correlation_id,
            )
        except Exception as exc:
            self._audit_manager.invoke(
                raw_url=url,
                parsed_url=None,
                exception=exc,
                correlation_id=self._correlation_id
            )
            raise

    def _security_checks(self) -> None:
        """Run security validations on parsed URL."""
        self.validate(raise_on_error=True)

    def _apply_parsed(self, components: Mapping[str, Optional[Any]]) -> None:
        """Apply parsed components to instance."""
        scheme_component = components.get("scheme")
        self._scheme = str(scheme_component) if scheme_component is not None else None
        userinfo_component = components.get("userinfo")
        self._userinfo = str(userinfo_component) if userinfo_component is not None else None
        host_component = components.get("host")
        self._host = str(host_component) if host_component is not None else None
        self._port = _normalize_port(components.get("port"))
        path_component = components.get("path")
        self._path = str(path_component) if path_component is not None else ""
        query_component = components.get("query")
        self._query = str(query_component) if query_component is not None else None
        fragment_component = components.get("fragment")
        self._fragment = str(fragment_component) if fragment_component is not None else None
        query_pairs = components.get("query_pairs")
        if isinstance(query_pairs, list):
            self._query_pairs = [
                (str(k), None if v is None else str(v))
                for k, v in query_pairs
            ]
        else:
            self._query_pairs = list(getattr(self._parser, "query_pairs", []))
        findings = components.get("security_findings")
        self._security_findings = list(findings) if isinstance(findings, list) else []

    @property
    def scheme(self) -> Optional[str]:
        """The URL scheme (e.g., 'http', 'https')."""
        return self._scheme

    @property
    def host(self) -> Optional[str]:
        """The host component (IDNA-encoded if applicable)."""
        return self._host

    @property
    def port(self) -> Optional[int]:
        """The explicit port, or None if not present."""
        return self._port

    @property
    def userinfo(self) -> Optional[str]:
        """The userinfo component (e.g., 'user:pass')."""
        return self._userinfo

    @property
    def path(self) -> str:
        """The path component (always a string, may be empty)."""
        return self._path

    @property
    def query(self) -> Optional[str]:
        """The query string (without '?'), or None if not present."""
        return self._query

    @property
    def fragment(self) -> Optional[str]:
        """The fragment string (without '#'), or None if not present."""
        return self._fragment

    @property
    def query_params(self) -> QueryPairs:
        """Return query parameters as list of (key, value) tuples."""
        return list(self._query_pairs)

    @property
    def netloc(self) -> str:
        """Return the network location (userinfo@host:port)."""
        return self._builder.build_netloc(
            self._userinfo, self._host, self._port, self._scheme
        )

    @property
    def effective_port(self) -> Optional[int]:
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

    def copy(self, **overrides: Any) -> 'URL':
        """Create a copy with optional component overrides.

        Args:
            overrides: Components to override (scheme, host, port, path, query, fragment, userinfo, query_pairs).
        Returns:
            A new URL instance with the specified overrides.
        Raises:
            InvalidURLError: If overrides are invalid.
        """
        _validate_copy_overrides(overrides)
        components = self._to_dict()
        components.update(overrides)
        components["port"] = _normalize_port(components.get("port"))

        new_url = object.__new__(URL)
        new_url.recognized_scheme = self.recognized_scheme
        new_url._parser = self._parser
        new_url._builder = self._builder
        new_url._strict = self._strict
        new_url._debug = self._debug
        new_url._check_dns = self._check_dns
        new_url._check_phishing = self._check_phishing
        new_url._security_policy = self._security_policy
        new_url._correlation_id = self._correlation_id
        new_url._apply_parsed(components)
        new_url._security_findings = []
        new_url.validate(raise_on_error=True)
        return new_url

    def with_scheme(self, scheme: Optional[str]) -> 'URL':
        """Return new URL with different scheme."""
        return self.copy(scheme=scheme)

    def with_host(self, host: Optional[str]) -> 'URL':
        """Return new URL with different host."""
        return self.copy(host=host)

    def with_port(self, port: Optional[int]) -> 'URL':
        """Return new URL with different port."""
        return self.copy(port=port)

    def with_path(self, path: str) -> 'URL':
        """Return new URL with different path."""
        return self.copy(path=path)

    def with_query(self, query: Optional[str]) -> 'URL':
        """Return new URL with different query string."""
        return self.copy(query=query)

    def with_fragment(self, fragment: Optional[str]) -> 'URL':
        """Return new URL with different fragment."""
        return self.copy(fragment=fragment)

    def with_userinfo(self, userinfo: Optional[str]) -> 'URL':
        """Return new URL with different userinfo."""
        return self.copy(userinfo=userinfo)

    def with_netloc(self, netloc: str) -> 'URL':
        """Return new URL with different netloc (userinfo@host:port)."""
        parser = Parser()
        userinfo, host, port = parser.parse_netloc(netloc, require_host=bool(netloc))
        if port is None and self._scheme and host:
            port = DEFAULT_PORTS.get(self._scheme.lower())
        return self.copy(userinfo=userinfo, host=host, port=port)

    def with_query_param(self, key: str, value: Optional[str] = None) -> 'URL':
        """Return new URL with added query parameter."""
        _check_type(key, str, "key")
        normalized_key = str(key)
        new_query = cast(str, self._builder.add_param(self._query, normalized_key, value))
        return self.copy(query=new_query)

    def without_query_param(self, key: str) -> 'URL':
        """Return new URL with query parameter removed."""
        _check_type(key, str, "key")
        normalized_key = str(key)
        new_query = cast(str, self._builder.remove_param(self._query, normalized_key))
        return self.copy(query=new_query)

    def without_query(self) -> 'URL':
        """Return new URL without query string or fragment."""
        return self.copy(query=None, query_pairs=[], fragment=None)

    def same_origin(self, other: 'URL') -> bool:
        """Check if this URL has the same origin as another URL."""
        return self.origin == other.origin

    def canonicalize(self) -> 'URL':
        """Return a canonicalized copy of this URL (lowercase scheme/host, sorted query, normalized path)."""
        canonical_scheme = self._scheme.lower() if self._scheme else None
        canonical_host = str(self._host).lower() if self._host else None
        canonical_port = self._port
        if canonical_scheme and canonical_port == DEFAULT_PORTS.get(canonical_scheme):
            canonical_port = None
        canonical_path = self._builder.normalize_path(self._path) if self._path else ""
        sorted_pairs = sorted(self._query_pairs, key=lambda x: (x[0], x[1] or ""))
        canonical_query = self._builder.serialize_query(sorted_pairs) if sorted_pairs else None

        new_url = self.copy(
            scheme=canonical_scheme, host=canonical_host,
            port=canonical_port, path=canonical_path, query=canonical_query,
        )
        new_url._query_pairs = sorted_pairs
        return new_url

    def is_semantically_equal(self, other: 'URL') -> bool:
        """Check semantic equality after normalization."""
        if not isinstance(other, URL):
            return False
        return self.canonicalize().as_string() == other.canonicalize().as_string()

    def as_string(self, *, mask_password: bool = False) -> str:
        """Return URL as string, optionally masking password in userinfo."""
        components = self._to_dict()
        if mask_password and components.get("userinfo"):
            userinfo = components["userinfo"]
            if ":" in userinfo:
                username, _, _ = userinfo.partition(":")
                components["userinfo"] = f"{username}:{PASSWORD_MASK}"
        return self._builder.compose(components)

    @property
    def security_findings(self) -> List[SecurityFinding]:
        """Return the last computed security findings for this URL instance."""
        return list(self._security_findings)

    def validate(
        self,
        *,
        policy: Optional[SecurityPolicy] = None,
        raise_on_error: bool = False,
        raw_url: Optional[str] = None,
    ) -> List[SecurityFinding]:
        """Validate this URL against a security policy and return findings."""
        effective_policy = policy if policy is not None else self._security_policy
        candidate_url = raw_url if raw_url is not None else self.as_string()
        findings = validate_url_security(
            candidate_url,
            policy=effective_policy,
            check_dns=self._check_dns,
            check_phishing=self._check_phishing,
            raise_on_error=raise_on_error,
        )
        self._security_findings = list(findings)
        return list(findings)

    def redacted(self) -> str:
        """Return a log-safe representation with sensitive values redacted."""
        return redact_url_for_logs(self.as_string())

    def _to_dict(self) -> Dict[str, Any]:
        """Convert URL to dictionary of components."""
        return {
            "scheme": self._scheme, "userinfo": self._userinfo, "host": self._host,
            "port": self._port, "path": self._path, "query": self._query,
            "fragment": self._fragment, "query_pairs": list(self._query_pairs),
        }

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
        return hash((self._scheme, self._userinfo, self._host, self._port,
                     self._path, self._query, self._fragment))

    def __eq__(self, other: object) -> bool:
        """Check equality with another URL object."""
        if not isinstance(other, URL):
            return NotImplemented
        return self.as_string() == other.as_string()

    def __lt__(self, other: object) -> bool:
        """Compare URLs lexicographically for sorting."""
        if not isinstance(other, URL):
            return NotImplemented
        return self.as_string() < other.as_string()

    def __le__(self, other: object) -> bool:
        """Compare URLs lexicographically for sorting."""
        if not isinstance(other, URL):
            return NotImplemented
        return self.as_string() <= other.as_string()

    def __gt__(self, other: object) -> bool:
        """Compare URLs lexicographically for sorting."""
        if not isinstance(other, URL):
            return NotImplemented
        return self.as_string() > other.as_string()

    def __ge__(self, other: object) -> bool:
        """Compare URLs lexicographically for sorting."""
        if not isinstance(other, URL):
            return NotImplemented
        return self.as_string() >= other.as_string()


def _normalize_port(value: Optional[Any]) -> Optional[int]:
    """Normalize port value to int or None."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        if not value.isdigit():
            raise InvalidURLError("Port must be numeric.")
        candidate = int(value)
    elif isinstance(value, int):
        candidate = value
    else:
        raise InvalidURLError("Port must be an integer or numeric string.")
    if not 0 < candidate < 65536:
        raise InvalidURLError("Port must be between 1 and 65535.")
    return candidate


def _validate_copy_overrides(overrides: Dict[str, Any]) -> None:
    """Validate copy() override arguments."""
    valid_keys = {'scheme', 'host', 'port', 'path', 'query', 'fragment',
                  'userinfo', 'query_pairs'}
    invalid_keys = set(overrides.keys()) - valid_keys
    if invalid_keys:
        raise InvalidURLError(f"Invalid override(s): {', '.join(sorted(invalid_keys))}")
    for key in ('scheme', 'host', 'path', 'query', 'fragment'):
        if key in overrides and overrides[key] is not None:
            if not isinstance(overrides[key], str):
                raise InvalidURLError(f"{key} must be a string")
    if 'userinfo' in overrides and overrides['userinfo'] is not None:
        if not isinstance(overrides['userinfo'], str):
            raise InvalidURLError("userinfo must be a string")
        if not is_valid_userinfo(overrides['userinfo']):
            raise InvalidURLError("Invalid userinfo format.")


__all__ = [
    "URL", "parse_relative_reference", "build_relative_reference", "round_trip_relative",
]
