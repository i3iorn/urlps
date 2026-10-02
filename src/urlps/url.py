"""High-level immutable URL representation and manipulation.

This module provides the main URL class and helpers for parsing, building, and manipulating URLs.

Public API:
    - URL: Immutable URL object with rich methods for access and modification.
    - parse_relative_reference, build_relative_reference, round_trip_relative: Relative URL helpers.

A URL holds two values: its normalized components (``URLParts``) and its
context (the policy it was validated under, the check flags, audit and the
custom-scheme setting). Serialization, derivation and validation work on
those; none of them reaches into the URL's other private state.

Audit hooks are supplied per call via the ``audit=AuditConfig(...)`` parameter
rather than by module-level setters.
"""

from __future__ import annotations

import functools
import warnings
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from typing import Any

from . import _mutations, _serialization
from ._audit import NO_OP_AUDIT_MANAGER, AuditConfig, AuditManager
from ._builder import Builder, QueryPairs
from ._components import SecurityFinding, URLParts
from ._helpers import _check_type, _normalize_port
from ._parser import Parser
from ._parser import parse_url as parse_components
from ._relative import build_relative_reference, parse_relative_reference, round_trip_relative
from ._security import (
    ParsedComponents,
    SecurityPolicy,
    extract_host_and_path,
    has_parser_confusion,
    has_path_traversal,
    is_open_redirect_risk,
    redact_component,
    redact_url_for_logs,
    validate_url_security,
)
from ._validation import Validator
from .constants import DEFAULT_PORTS, MAX_URL_LENGTH
from .exceptions import InvalidURLError, URLParseError, URLpError

_DEFAULT_BUILDER = Builder()


def _redact_exception(exc: BaseException) -> None:
    """Redact the offending value an exception carries, in place.

    ``str(exc)`` includes ``value``, and both end up in logs and error
    responses; the raw input is only kept with ``debug=True``.
    """
    if isinstance(exc, URLpError):
        exc.value = redact_component(exc.value, exc.component)


@dataclass(frozen=True, slots=True, eq=False)
class _URLContext:
    """Everything a URL carries besides its components.

    Derived URLs share their source's context, so ``with_host()`` is
    validated under the same policy, flags and scheme rules as the parse
    that produced the original.
    """

    policy: SecurityPolicy
    check_dns: bool
    check_phishing: bool
    allow_custom_scheme: bool
    debug: bool
    correlation_id: str | None
    audit_manager: AuditManager
    builder: Builder
    #: Deprecated ``URL(parser=...)`` injection; None means the module parser.
    parser: Parser | None = None


def _parts_from_mapping(components: Mapping[str, Any], parser: Parser) -> URLParts:
    """Coerce the dict a (deprecated, possibly custom) ``Parser.parse()`` returns."""

    def text(name: str) -> str | None:
        value = components.get(name)
        return None if value is None else str(value)

    query_pairs = components.get("query_pairs")
    if not isinstance(query_pairs, list):
        # A custom parser predating the key: fall back to its attribute.
        query_pairs = list(getattr(parser, "query_pairs", []))
    return URLParts(
        scheme=text("scheme"),
        userinfo=text("userinfo"),
        host=text("host"),
        port=_normalize_port(components.get("port")),
        path=text("path") or "",
        query=text("query"),
        fragment=text("fragment"),
        query_pairs=tuple((str(k), None if v is None else str(v)) for k, v in query_pairs),
    )


@functools.total_ordering
class URL:
    """Immutable URL representation.

    URLs are immutable by default. Use `copy()` or `with_*` methods to create modified versions.

    Args:
        url: The URL string to parse.
        allow_custom_scheme: Accept a non-standard scheme (anything other
            than http, https, ftp, ftps, sftp, ws, wss). Derived URLs inherit it.
        debug: If True, exceptions carry the raw input as ``value``. By
            default credentials and sensitive query/fragment values in it are
            redacted, since exception text routinely reaches logs.
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
        parser: Deprecated. A ``Parser`` instance; only its ``custom_scheme``
            setting was ever needed -- pass ``allow_custom_scheme`` instead.
        builder: Deprecated. A ``Builder`` used for serialization.

    Raises:
        URLParseError: If the URL is invalid or fails security checks.
    """

    __slots__ = (
        "_context",
        "_frozen",
        "_parts",
        "_recognized_scheme",
        "_security_findings",
        "_serialized",
    )

    def __setattr__(self, name: str, value: Any) -> None:
        """Block attribute assignment once construction has finished.

        A URL is validated exactly once, at construction. Without this guard a
        caller could do ``u._parts = ...`` and walk straight past every check
        that ``parse_url()`` just ran -- the object would still report itself
        as validated while pointing somewhere else entirely. Construction,
        ``_from_parts``, unpickling and the ``str()`` cache go through
        ``object.__setattr__`` deliberately.
        """
        if getattr(self, "_frozen", False):
            raise AttributeError(
                f"URL is immutable; use with_*() or copy() to derive a new URL (tried to set {name!r})"
            )
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        """Block attribute deletion -- otherwise ``del u._parts`` is a trivial bypass of __setattr__."""
        if getattr(self, "_frozen", False):
            raise AttributeError(
                f"URL is immutable; use with_*() or copy() to derive a new URL (tried to delete {name!r})"
            )
        object.__delattr__(self, name)

    def __init__(
        self,
        url: str,
        *,
        allow_custom_scheme: bool = False,
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
        _check_type(allow_custom_scheme, bool, "allow_custom_scheme")
        _check_type(debug, bool, "debug")
        _check_type(check_dns, bool, "check_dns")
        _check_type(check_phishing, bool, "check_phishing")
        if audit is not None and not isinstance(audit, AuditConfig):
            raise TypeError(f"audit must be AuditConfig, got {type(audit).__name__}")
        if parser is not None:
            warnings.warn(
                "URL(parser=...) is deprecated and will be removed in a future major release; "
                "pass allow_custom_scheme=... instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            allow_custom_scheme = allow_custom_scheme or parser.custom_scheme
        if builder is not None:
            warnings.warn(
                "URL(builder=...) is deprecated and will be removed in a future major release.",
                DeprecationWarning,
                stacklevel=2,
            )

        policy = security_policy if security_policy is not None else SecurityPolicy.strict(check_dns=check_dns)
        self._context = _URLContext(
            policy=policy,
            # A check enabled on either the argument or the policy runs. These
            # flags are passed on as explicit overrides at validation time, so
            # a plain False here used to switch off a policy's check_dns=True.
            check_dns=check_dns or policy.check_dns,
            check_phishing=check_phishing or policy.check_phishing,
            allow_custom_scheme=allow_custom_scheme,
            debug=debug,
            correlation_id=correlation_id,
            audit_manager=AuditManager(audit) if audit is not None else NO_OP_AUDIT_MANAGER,
            builder=builder if builder is not None else _DEFAULT_BUILDER,
            parser=parser,
        )
        self._parse_and_validate(url)
        object.__setattr__(self, "_frozen", True)

    @classmethod
    def _from_parts(cls, parts: URLParts, context: _URLContext, *, recognized_scheme: bool | None) -> URL:
        """Build and validate a URL from components -- how every derived URL is made."""
        url = object.__new__(cls)
        # Same reason as in __init__: __setattr__ reads this on every write.
        object.__setattr__(url, "_frozen", False)
        url._context = context
        url._initialize(parts, recognized_scheme)
        url._security_findings = url.validate(raise_on_error=True)
        object.__setattr__(url, "_frozen", True)
        return url

    def _initialize(self, parts: URLParts, recognized_scheme: bool | None) -> None:
        self._parts = parts
        self._recognized_scheme = recognized_scheme
        self._security_findings: list[SecurityFinding] = []
        self._serialized: str | None = None

    def _parse(self, url: str) -> tuple[URLParts, bool | None]:
        """Parse ``url`` into components, statelessly unless a legacy parser was injected."""
        context = self._context
        if context.parser is None:
            result = parse_components(url, allow_custom_scheme=context.allow_custom_scheme)
            return result.parts, result.recognized_scheme
        components = context.parser.parse(url)
        # From the result, not the parser's state: a shared Parser may
        # already hold another thread's parse. Custom parsers that return
        # only the component keys keep the old attribute fallback.
        recognized = (
            components["recognized_scheme"] if "recognized_scheme" in components else context.parser.recognized_scheme
        )
        return _parts_from_mapping(components, context.parser), recognized

    def _parse_and_validate(self, url: str) -> None:
        """Parse URL and run security validations."""
        if not url.strip():
            raise URLParseError("A non-empty URL string is required.")
        if len(url) > MAX_URL_LENGTH:
            raise URLParseError("URL length exceeds maximum allowed size.")
        if not Validator.is_url_safe_string(url):
            raise URLParseError("URL contains invalid control characters.")

        context = self._context
        try:
            if context.policy.enforce_parser_confusion and has_parser_confusion(url):
                _, pre_path = extract_host_and_path(url)
                if not (pre_path and (is_open_redirect_risk(pre_path) or has_path_traversal(pre_path))):
                    raise InvalidURLError("URL contains ambiguous syntax that could cause parser confusion.")
            parts, recognized = self._parse(url)
            self._initialize(parts, recognized)
            self._security_findings = self.validate(raise_on_error=True, raw_url=url)
            context.audit_manager.invoke(
                raw_url=url,
                parsed_url=self,
                exception=None,
                correlation_id=context.correlation_id,
            )
        except Exception as exc:
            if not context.debug:
                _redact_exception(exc)
            context.audit_manager.invoke(
                raw_url=url, parsed_url=None, exception=exc, correlation_id=context.correlation_id
            )
            raise

    # ------------------------------------------------------------------
    # Components
    # ------------------------------------------------------------------

    @property
    def scheme(self) -> str | None:
        """The URL scheme (e.g., 'http', 'https')."""
        return self._parts.scheme

    @property
    def host(self) -> str | None:
        """The host component (IDNA-encoded if applicable)."""
        return self._parts.host

    @property
    def port(self) -> int | None:
        """The port: the explicit one, or the scheme's default; None if the scheme has none."""
        return self._parts.port

    @property
    def userinfo(self) -> str | None:
        """The userinfo component (e.g., 'user:pass')."""
        return self._parts.userinfo

    @property
    def path(self) -> str:
        """The path component (always a string, may be empty)."""
        return self._parts.path

    @property
    def query(self) -> str | None:
        """The query string (without '?'), or None if not present."""
        return self._parts.query

    @property
    def fragment(self) -> str | None:
        """The fragment string (without '#'), or None if not present."""
        return self._parts.fragment

    @property
    def query_params(self) -> QueryPairs:
        """Return query parameters as list of (key, value) tuples."""
        return list(self._parts.query_pairs)

    @property
    def query_pairs(self) -> QueryPairs:
        """Alias for query_params."""
        return self.query_params

    @property
    def recognized_scheme(self) -> bool | None:
        """Whether the scheme is a standard one; None for a scheme-less URL."""
        return self._recognized_scheme

    @property
    def security_policy(self) -> SecurityPolicy:
        """The policy this URL was validated under (and derived URLs will be)."""
        return self._context.policy

    def get_query_param(self, key: str, default: str | None = None) -> str | None:
        """Return the first value for ``key``, or ``default`` if absent.

        A key present with no ``=value`` (``?flag&x=1``) has a value of
        ``None`` in ``query_params``, which is returned as-is -- it is
        distinct from the key being absent entirely, which returns
        ``default``.

        Example:
            >>> url = parse_url("https://example.com/?id=1&id=2&flag")
            >>> url.get_query_param("id")
            '1'
            >>> url.get_query_param("flag")
            >>> url.get_query_param("missing", default="none")
            'none'
        """
        for k, v in self._parts.query_pairs:
            if k == key:
                return v
        return default

    def get_query_param_all(self, key: str) -> list[str | None]:
        """Return every value for ``key``, in order; ``[]`` if absent.

        Example:
            >>> url = parse_url("https://example.com/?id=1&id=2")
            >>> url.get_query_param_all("id")
            ['1', '2']
            >>> url.get_query_param_all("missing")
            []
        """
        return [v for k, v in self._parts.query_pairs if k == key]

    @property
    def netloc(self) -> str:
        """Return the network location (userinfo@host:port)."""
        parts = self._parts
        return self._context.builder.build_netloc(parts.userinfo, parts.host, parts.port, parts.scheme)

    @property
    def effective_port(self) -> int | None:
        """Return explicit port or scheme default."""
        parts = self._parts
        if parts.port is not None:
            return parts.port
        return DEFAULT_PORTS.get(parts.scheme.lower()) if parts.scheme else None

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
        scheme, host = self._parts.scheme, self._parts.host
        if not scheme or not host:
            raise InvalidURLError("Cannot compute origin for relative URL.")
        port = self.effective_port
        if port and DEFAULT_PORTS.get(scheme.lower()) == port:
            port = None
        if port:
            return f"{scheme}://{host}:{port}"
        return f"{scheme}://{host}"

    # ------------------------------------------------------------------
    # Derivation
    # ------------------------------------------------------------------

    def _derive(self, make_overrides: Callable[[], Mapping[str, Any]]) -> URL:
        """The one redaction boundary for derived URLs (and their override parsing)."""
        try:
            return _mutations.derive(self, make_overrides())
        except Exception as exc:
            if not self._context.debug:
                _redact_exception(exc)
            raise

    def copy(self, **overrides: Any) -> URL:
        """Create a copy with optional component overrides.

        Args:
            overrides: Components to override (scheme, host, port, path, query, fragment, userinfo, query_pairs).
        Returns:
            A new URL instance with the specified overrides.
        Raises:
            InvalidURLError: If overrides are invalid.
        """
        return self._derive(lambda: overrides)

    def with_scheme(self, scheme: str | None) -> URL:
        """Return new URL with different scheme.

        `scheme=None` clears the scheme, consistent with every other `with_*`
        method (`with_host`, `with_query`, `with_fragment`, `with_userinfo`)
        accepting `None` to clear their component. Non-str, non-None values are
        rejected, and the scheme is held to the same allowlist as parsing.
        """
        return self.copy(scheme=scheme)

    def with_host(self, host: str | None) -> URL:
        """Return new URL with different host."""
        return self.copy(host=host)

    def with_port(self, port: int | None) -> URL:
        """Return new URL with different port."""
        return self.copy(port=port)

    def with_path(self, path: str) -> URL:
        """Return new URL with different path."""
        return self.copy(path=path)

    def with_query(self, query: str | None) -> URL:
        """Return new URL with different query string."""
        return self.copy(query=query)

    def with_fragment(self, fragment: str | None) -> URL:
        """Return new URL with different fragment."""
        return self.copy(fragment=fragment)

    def with_userinfo(self, userinfo: str | None) -> URL:
        """Return new URL with different userinfo."""
        return self.copy(userinfo=userinfo)

    def with_netloc(self, netloc: str) -> URL:
        """Return new URL with different netloc (userinfo@host:port)."""
        return self._derive(lambda: _mutations.netloc_overrides(netloc, self._parts.scheme))

    def with_query_param(self, key: str, value: str | None = None) -> URL:
        """Return new URL with added query parameter."""
        _check_type(key, str, "key")
        return self.copy(query=self._context.builder.add_param(self._parts.query, key, value))

    def without_query_param(self, key: str) -> URL:
        """Return new URL with query parameter removed."""
        _check_type(key, str, "key")
        return self.copy(query=self._context.builder.remove_param(self._parts.query, key))

    def without_query(self) -> URL:
        """Return new URL without query string or fragment."""
        return self.copy(query=None, query_pairs=[], fragment=None)

    def same_origin(self, other: URL) -> bool:
        """Check if this URL has the same origin as another URL."""
        return self.origin == other.origin

    def canonicalize(self) -> URL:
        """Return a canonicalized copy of this URL (lowercase scheme/host, sorted query, normalized path)."""
        return self.copy(**_serialization.canonical_overrides(self._parts, self._context.builder))

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

    # ------------------------------------------------------------------
    # Pickling
    # ------------------------------------------------------------------

    #: Context fields that are URL data. The rest -- the audit manager (a
    #: lock and user callbacks; a deserialized URL firing someone's audit
    #: callbacks would be surprising), the builder and the deprecated parser
    #: -- are machinery, rebuilt fresh on unpickle.
    _PICKLED_CONTEXT = ("policy", "check_dns", "check_phishing", "allow_custom_scheme", "debug", "correlation_id")

    def __getstate__(self) -> dict[str, Any]:
        # The str() cache is left out: it is cheap to rebuild, and a hash of
        # it is salted per process anyway.
        context = self._context
        return {
            "parts": {field.name: getattr(self._parts, field.name) for field in fields(URLParts)},
            "recognized_scheme": self._recognized_scheme,
            "security_findings": list(self._security_findings),
            **{name: getattr(context, name) for name in URL._PICKLED_CONTEXT},
        }

    def __setstate__(self, state: Mapping[str, Any]) -> None:
        """Restore via object.__setattr__ -- the default path trips the guard.

        A restored URL is *not* re-validated: pickle round-trips trusted
        state. Never unpickle data from an untrusted source -- unpickling can
        execute arbitrary code, so no check here could make that safe. To
        move URLs across a trust boundary, send ``str(url)`` and
        ``parse_url()`` it on the other side.

        Pickles made by urlps 1.1 (one attribute per component) still load.
        """
        if "parts" not in state:
            state = _upgrade_legacy_state(state)
        object.__setattr__(self, "_frozen", False)
        object.__setattr__(
            self,
            "_context",
            _URLContext(
                policy=state["policy"],
                check_dns=state["check_dns"],
                check_phishing=state["check_phishing"],
                allow_custom_scheme=state["allow_custom_scheme"],
                debug=state["debug"],
                correlation_id=state["correlation_id"],
                audit_manager=NO_OP_AUDIT_MANAGER,
                builder=_DEFAULT_BUILDER,
            ),
        )
        parts = dict(state["parts"])
        parts["query_pairs"] = tuple(tuple(pair) for pair in parts.get("query_pairs") or ())
        self._initialize(URLParts(**parts), state["recognized_scheme"])
        object.__setattr__(self, "_security_findings", list(state["security_findings"]))
        object.__setattr__(self, "_frozen", True)

    # ------------------------------------------------------------------
    # Serialization, comparison, validation
    # ------------------------------------------------------------------

    def as_string(self, *, mask_password: bool = False) -> str:
        """Return URL as string, optionally masking password in userinfo."""
        if mask_password:
            return _serialization.as_string(self._parts, self._context.builder, mask_password=True)
        serialized = self._serialized
        if serialized is None:
            serialized = _serialization.as_string(self._parts, self._context.builder)
            # Immutable, so the string never changes; cached for __hash__/__eq__.
            object.__setattr__(self, "_serialized", serialized)
        return serialized

    def is_semantically_equal(self, other: URL) -> bool:
        """Check semantic equality after normalization."""
        if not isinstance(other, URL):
            return False
        return self.canonicalize().as_string() == other.canonicalize().as_string()

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
        context = self._context
        parts = self._parts
        findings = validate_url_security(
            raw_url if raw_url is not None else self.as_string(),
            policy=policy if policy is not None else context.policy,
            check_dns=None if policy is not None else context.check_dns,
            check_phishing=None if policy is not None else context.check_phishing,
            raise_on_error=raise_on_error,
            # The components this URL actually exposes and serializes. Without
            # them the checks re-parse the string themselves and can land on a
            # different host than the parser did.
            parsed=ParsedComponents(host=parts.host, port=parts.port, userinfo=parts.userinfo, path=parts.path),
            debug=context.debug,
        )
        return list(findings)

    def redacted(self) -> str:
        """Return a log-safe representation with sensitive values redacted."""
        return redact_url_for_logs(self.as_string())

    def _to_dict(self) -> dict[str, Any]:
        """Convert URL to dictionary of components."""
        return self._parts.as_mapping()

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
        """Hash exactly what ``==`` compares: the serialized URL.

        Hashing the raw components broke ``a == b -> hash(a) == hash(b)``:
        ``https://h/`` with port 443 and with port None serialize identically
        but hashed apart. It also makes a URL hash like the string it equals.
        """
        return hash(self.as_string())

    def __eq__(self, other: object) -> bool:
        """Equal to another URL, or a plain string, that serializes identically (no canonicalization)."""
        if isinstance(other, URL):
            return self.as_string() == other.as_string()
        if isinstance(other, str):
            return self.as_string() == other
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        """Order URLs (or a URL and a string) lexicographically by their serialization."""
        if isinstance(other, URL):
            return self.as_string() < other.as_string()
        if isinstance(other, str):
            return self.as_string() < other
        return NotImplemented


def _upgrade_legacy_state(state: Mapping[str, Any]) -> dict[str, Any]:
    """Convert a urlps 1.1 pickle state (one attribute per component) to the current shape."""
    recognized = state.get("recognized_scheme")
    return {
        "parts": {
            "scheme": state.get("_scheme"),
            "userinfo": state.get("_userinfo"),
            "host": state.get("_host"),
            "port": state.get("_port"),
            "path": state.get("_path") or "",
            "query": state.get("_query"),
            "fragment": state.get("_fragment"),
            "query_pairs": state.get("_query_pairs") or (),
        },
        "recognized_scheme": recognized,
        "security_findings": state.get("_security_findings") or [],
        "policy": state.get("_security_policy") or SecurityPolicy.strict(),
        "check_dns": bool(state.get("_check_dns")),
        "check_phishing": bool(state.get("_check_phishing")),
        # 1.1 kept this on the (unpickled) parser; a custom scheme implies it.
        "allow_custom_scheme": recognized is False,
        "debug": bool(state.get("_debug")),
        "correlation_id": state.get("_correlation_id"),
    }


__all__ = [
    "URL",
    "build_relative_reference",
    "parse_relative_reference",
    "round_trip_relative",
]
