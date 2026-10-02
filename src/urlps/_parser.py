"""URL parsing module with stateless functions and Parser class."""

from __future__ import annotations

from collections.abc import Set as AbstractSet
from typing import Any
from urllib.parse import unquote

from ._builder import QueryPairs, decode_query_pairs
from ._cache_config import PARSER_CACHE_SIZE, bounded_lru_cache, cache_info
from ._cache_config import clear_caches as clear_registered_caches
from ._components import ParseResult, URLParts
from ._host import is_ascii_digits, looks_like_ipv4, port_number
from ._normalize import normalize_host, normalize_percent_encoding, normalize_userinfo
from ._resolve import normalize_dot_segments
from ._security._unicode.uts46 import IdnaError, canonical_host
from ._validation import Validator, is_valid_userinfo, scheme_rejection
from .constants import (
    DEFAULT_PORTS,
    MAX_FRAGMENT_LENGTH,
    MAX_HOST_LENGTH,
    MAX_PATH_LENGTH,
    MAX_QUERY_LENGTH,
    MAX_SCHEME_LENGTH,
    OFFICIAL_SCHEMES,
    SCHEMES_NO_PORT,
    STANDARD_SCHEMES,
)
from .exceptions import (
    FragmentEncodingError,
    HostValidationError,
    MissingHostError,
    PortValidationError,
    QueryParsingError,
    UnsupportedSchemeError,
    URLParseError,
    UserInfoParsingError,
)


def parse_scheme(
    url: str, allow_custom: bool = False, *, allowed_schemes: AbstractSet[str] = STANDARD_SCHEMES
) -> tuple[str | None, str, bool | None, bool]:
    """Parse scheme from URL.

    Returns (scheme, remainder, recognized_scheme, has_authority). The colon
    is only treated as a scheme separator when nothing before it contains a
    '/', '?', or '#' -- otherwise it belongs to a path/query/fragment of an
    otherwise scheme-less (relative) reference and must not be mistaken for
    one just because '://' happens to appear later in the string (e.g. in a
    query value like '?next=http://host').
    """
    colon_index = url.find(":")
    if colon_index <= 0:
        return None, url, None, False

    scheme_candidate = url[:colon_index]
    if "/" in scheme_candidate or "?" in scheme_candidate or "#" in scheme_candidate:
        return None, url, None, False

    rest = url[colon_index + 1 :]
    has_authority = rest.startswith("//")
    if has_authority:
        remainder = rest[2:]
    else:
        remainder = rest
        if (
            remainder
            and not remainder.startswith("/")
            and not remainder.startswith("?")
            and not remainder.startswith("#")
        ):
            if not Validator.is_valid_scheme(scheme_candidate.lower()):
                return None, url, None, False

    if len(scheme_candidate) > MAX_SCHEME_LENGTH:
        raise URLParseError(
            f"Scheme exceeds maximum length of {MAX_SCHEME_LENGTH}.", value=scheme_candidate, component="scheme"
        )

    scheme_lower = scheme_candidate.lower()
    # RFC 3986 grammar first, even for a custom scheme: "a_b" is no scheme.
    if not Validator.is_valid_scheme(scheme_lower):
        raise URLParseError(f"Invalid URL scheme: {scheme_candidate}", value=scheme_candidate, component="scheme")
    # The policy's scheme rule, applied here so a dangerous scheme is refused
    # before the rest of the URL is read. Accepting any well-formed scheme by
    # default let parse_url() vet links such as ms-msdt:, search-ms: or
    # smb:// that hand the URL to an OS protocol handler.
    rejection = scheme_rejection(scheme_lower, allow_custom=allow_custom, allowed=allowed_schemes)
    if rejection is not None:
        code, message = rejection
        raise UnsupportedSchemeError(message, value=scheme_candidate, component="scheme", code=code)
    return scheme_lower, remainder, scheme_lower in OFFICIAL_SCHEMES, has_authority


def split_fragment(url: str) -> tuple[str, str | None]:
    """Split fragment from URL."""
    # partition() alone finds and splits in one scan; checking "#" in url
    # first would scan the string twice for the same answer.
    base, sep, fragment = url.partition("#")
    return base, fragment if sep else None


def split_query(url: str) -> tuple[str, str | None]:
    """Split query string from URL."""
    base, sep, query = url.partition("?")
    return base, query if sep else None


def split_authority(url: str) -> tuple[str, str]:
    """Split authority from path in URL."""
    if not url:
        return "", ""
    authority, sep, path = url.partition("/")
    return authority, f"/{path}" if sep else ""


def normalize_userinfo_component(userinfo: str) -> str:
    """Validate a userinfo and store it the way the parser does.

    Anything outside the RFC 3986 userinfo grammar is escaped, so str(url)
    can only ever be read with this host. "http://169.254.169.254\\@example.com/"
    is host example.com here but host 169.254.169.254 to a WHATWG parser
    (browsers, Node), which treats "\\" as "/"; "%5C" is unambiguous.
    """
    if not is_valid_userinfo(userinfo):
        raise UserInfoParsingError("Invalid authentication section in URL.", value=userinfo, component="userinfo")
    try:
        return normalize_userinfo(userinfo)
    except UnicodeEncodeError as exc:
        raise UserInfoParsingError("Userinfo is not valid Unicode.", component="userinfo") from exc


def parse_userinfo(authority: str) -> tuple[str | None, str]:
    """Parse userinfo from authority."""
    if not authority or "@" not in authority:
        return None, authority or ""
    auth_segment, _, host = authority.partition("@")
    return normalize_userinfo_component(auth_segment), host


def parse_port(candidate: str) -> int:
    """Parse and validate port number.

    Args:
        candidate: Port string to parse (must be numeric)

    Returns:
        Validated port number as integer

    Raises:
        PortValidationError: If port is non-numeric or out of valid range (1-65535)
    """
    if not is_ascii_digits(candidate):
        raise PortValidationError(
            f"Port must be a positive integer. Received: {candidate!r}", value=candidate, component="port"
        )
    try:
        return port_number(candidate)
    except ValueError:
        raise PortValidationError(
            f"Port must be between 1 and 65535. Received: {candidate}", value=candidate, component="port"
        ) from None


def normalize_host_component(host: str) -> str:
    """Validate one host (no port) and return it exactly as the parser stores it.

    A bracketed IPv6 literal, a dotted IPv4 literal (anything shaped like
    one must be a valid one), or a hostname -- IDNA-encoded through the one
    entry point in _unicode/uts46.py, so the parser, derived URLs and the
    security checks never disagree on a host's form.
    """
    if len(host) > MAX_HOST_LENGTH:
        raise HostValidationError(f"Host exceeds maximum length of {MAX_HOST_LENGTH}.", value=host, component="host")
    if host.startswith("["):
        if not Validator.is_valid_ipv6(host):
            raise HostValidationError("Invalid IPv6 address format.", value=host, component="host")
        return normalize_host(host)
    if not host:
        raise MissingHostError("Host cannot be empty.", value=host, component="host")
    if looks_like_ipv4(host):
        if not Validator.is_valid_ipv4(host):
            raise HostValidationError("Invalid IPv4 address format.", value=host, component="host")
        return normalize_host(host)
    if not Validator.is_valid_host(host):
        raise HostValidationError("Host contains invalid characters.", value=host, component="host")
    try:
        return canonical_host(host)
    except IdnaError as exc:
        raise HostValidationError(f"Unable to IDNA-encode host: {exc}", value=host, component="host") from exc


def parse_ipv6_host(host_candidate: str) -> tuple[str, int | None]:
    """Parse IPv6 host with optional port."""
    closing = host_candidate.find("]")
    if closing == -1:
        raise HostValidationError("Invalid IPv6 host segment.", value=host_candidate, component="host")
    host = normalize_host_component(host_candidate[: closing + 1])
    remainder = host_candidate[closing + 1 :]
    port = None
    if remainder.startswith(":"):
        port = parse_port(remainder[1:])
    elif remainder:
        raise HostValidationError("Unexpected characters after IPv6 literal.", value=remainder, component="host")
    return host, port


def parse_regular_host(host_candidate: str) -> tuple[str, int | None]:
    """Parse regular hostname with optional port."""
    host_part, sep, port_part = host_candidate.partition(":")
    return normalize_host_component(host_part), parse_port(port_part) if sep else None


def parse_host(host_candidate: str, require_host: bool = False) -> tuple[str | None, int | None]:
    """Parse host and port from candidate string."""
    if not host_candidate:
        if require_host:
            raise MissingHostError("Host is required for absolute URLs.", value=host_candidate, component="host")
        return None, None
    host_candidate = host_candidate.strip()
    if len(host_candidate) > MAX_HOST_LENGTH:
        raise HostValidationError(
            f"Host exceeds maximum length of {MAX_HOST_LENGTH}.", value=host_candidate, component="host"
        )
    if host_candidate.startswith("["):
        return parse_ipv6_host(host_candidate)
    return parse_regular_host(host_candidate)


@bounded_lru_cache(maxsize=PARSER_CACHE_SIZE, group="parser")
def normalize_path(path_candidate: str) -> str:
    """RFC 3986 §6.2.2 path normalization: percent-encoding, then dot segments.

    In that order, as §6.2.2 lists them, so ``%2E%2E`` is removed as the
    ``..`` it denotes rather than decoded into one afterwards (which stored
    ``/a/../b`` while ``str(url)`` said ``/b``). The dot-segment step is the
    RFC algorithm shared with the builder and :func:`urlps.join`; it keeps
    empty segments (``/a//b``) and the trailing slash ``/a/b/..`` leaves.

    Performance: LRU cached to avoid re-normalizing common paths.
    """
    if not path_candidate:
        return ""
    # Decoded length, like the userinfo limit: the builder percent-encodes
    # non-ASCII on output (up to 12x longer), and str(url) must re-parse.
    if len(unquote(path_candidate)) > MAX_PATH_LENGTH:
        raise URLParseError(
            f"Path exceeds maximum length of {MAX_PATH_LENGTH}.", value=path_candidate, component="path"
        )
    return normalize_dot_segments(normalize_percent_encoding(path_candidate))


def parse_query_string(query_candidate: str | None) -> tuple[str | None, QueryPairs]:
    """Parse a query string into its original form plus decoded pairs.

    Returns ``(raw_query, pairs)``. The first element is the query string
    **exactly as received** -- parsing is non-destructive. Re-serializing
    from the decoded pairs instead would be lossy: ``quote_plus`` treats
    ``+``, ``&`` and ``=`` as safe, so a decoded literal ``+`` would decode
    as a space on the next pass and a decoded literal ``&`` would become a
    delimiter, splitting one parameter into two -- a parameter-smuggling
    vector, and fatal for signature verification or proxying.

    Re-encoding is now performed only where the caller explicitly asks for a
    different query (see ``URL.with_query_param`` / ``canonicalize``).

    """
    if query_candidate is None:
        return None, []
    if query_candidate == "":
        return "", []
    # Decoded length, like the path, fragment and userinfo limits: a query
    # re-serialized from its pairs (canonicalize(), with_query_param())
    # percent-encodes non-ASCII up to 12x longer, and must still parse.
    if len(unquote(query_candidate)) > MAX_QUERY_LENGTH:
        raise QueryParsingError(
            f"Query exceeds maximum length of {MAX_QUERY_LENGTH}.", value=query_candidate, component="query"
        )

    if not Validator.is_url_safe_string(query_candidate):
        raise QueryParsingError("Query string contains invalid characters.", value=query_candidate, component="query")

    return query_candidate, decode_query_pairs(query_candidate, error=QueryParsingError)


def parse_fragment_string(fragment_candidate: str | None) -> str | None:
    """Parse and validate fragment."""
    if fragment_candidate is None:
        return None
    if len(unquote(fragment_candidate)) > MAX_FRAGMENT_LENGTH:  # decoded, as for the path
        raise FragmentEncodingError(
            f"Fragment exceeds maximum length of {MAX_FRAGMENT_LENGTH}.", value=fragment_candidate, component="fragment"
        )
    if not Validator.is_valid_fragment(fragment_candidate):
        raise FragmentEncodingError(
            "Fragment contains invalid characters.", value=fragment_candidate, component="fragment"
        )
    return fragment_candidate


def apply_port_defaults(scheme: str | None, port: int | None, host: str | None) -> int | None:
    """Apply default ports and validate scheme/port combinations."""
    if scheme and scheme.lower() in SCHEMES_NO_PORT and port is not None:
        raise UnsupportedSchemeError(
            f"Scheme '{scheme}' does not allow explicit ports.", value=scheme, component="scheme/port"
        )
    if port is not None and host is None and (not scheme or scheme.lower() != "file"):
        raise PortValidationError("Port cannot be set without a host.", value=port, component="port")
    if port is not None:
        return port
    return DEFAULT_PORTS.get(scheme.lower()) if scheme else None


def parse_url(
    url: str, allow_custom_scheme: bool = False, *, allowed_schemes: AbstractSet[str] = STANDARD_SCHEMES
) -> ParseResult:
    """Parse a URL string into a ParseResult with all components.

    ``allow_custom_scheme`` accepts any well-formed scheme; otherwise the
    scheme must be in ``allowed_schemes`` (a policy's, or the standard set).
    """
    if not isinstance(url, str):
        raise URLParseError(f"URL must be a string, not {type(url).__name__}.", value=url, component="url")
    if not url.strip():
        raise URLParseError(f"URL cannot be empty or whitespace-only. Received: {url!r}", value=url, component="url")
    working = url.strip()
    scheme, remainder, recognized, has_authority = parse_scheme(
        working, allow_custom_scheme, allowed_schemes=allowed_schemes
    )

    if not scheme and remainder.startswith("//"):
        remainder = remainder[2:]

    remainder, fragment_str = split_fragment(remainder)
    remainder, query_str = split_query(remainder)

    if (scheme and has_authority) or (not scheme and url.startswith("//")):
        authority, path_candidate = split_authority(remainder)
    else:
        authority, path_candidate = "", remainder

    userinfo, host_candidate = parse_userinfo(authority)
    require_host = scheme is not None and scheme.lower() != "file" and has_authority
    host, port = parse_host(host_candidate, require_host=require_host)
    parts = _assemble(scheme, userinfo, host, port, path_candidate, query_str, fragment_str)

    return ParseResult(
        scheme=parts.scheme,
        userinfo=parts.userinfo,
        host=parts.host,
        port=parts.port,
        path=parts.path,
        query=parts.query,
        fragment=parts.fragment,
        query_pairs=list(parts.query_pairs),
        recognized_scheme=recognized,
        security_findings=[],
    )


def normalize_components(
    *,
    scheme: str | None,
    userinfo: str | None,
    host: str | None,
    port: int | None,
    path: str,
    query: str | None,
    fragment: str | None,
    require_host: bool = False,
) -> URLParts:
    """Run already-split components through the parser's own rules.

    The single construction path: ``parse_url`` splits a string and then
    applies exactly these steps, and every derived URL (``copy()``,
    ``with_*()``) is built here too, so a derived URL means what parsing its
    own string would. ``scheme`` must already be validated and lowercased.
    """
    if userinfo is not None:
        userinfo = normalize_userinfo_component(userinfo)
    if host:
        host = normalize_host_component(host)
    elif require_host:
        raise MissingHostError("Host is required for absolute URLs.", value=host, component="host")
    else:
        host = None
    return _assemble(scheme, userinfo, host, port, path, query, fragment)


def _assemble(
    scheme: str | None,
    userinfo: str | None,
    host: str | None,
    port: int | None,
    path: str,
    query: str | None,
    fragment: str | None,
) -> URLParts:
    """The steps after the authority: port defaults, path, query and fragment normalization."""
    port = apply_port_defaults(scheme, port, host)
    if host and path and not path.startswith("/"):
        # RFC 3986 §3.3: with an authority the path is empty or starts with
        # "/". A relative one would be serialized straight onto the
        # authority -- with_path("evil.com/x") on https://example.com/ read
        # back as host "example.comevil.com".
        path = "/" + path
    normalized_path = normalize_path(path)
    if host and not normalized_path:
        normalized_path = "/"
    raw_query, query_pairs = parse_query_string(query)
    # RFC 3986 §6.2.2.1/.2 applied to the stored components, not just at
    # serialization time -- otherwise `url.path` and `str(url)` disagree
    # about the same escape, and a caller comparing components sees a
    # different answer than one comparing strings.
    normalized_fragment = parse_fragment_string(fragment)
    return URLParts(
        scheme=scheme,
        userinfo=userinfo,
        host=host,
        port=port,
        path=normalized_path,
        query=None if raw_query is None else normalize_percent_encoding(raw_query),
        fragment=None if normalized_fragment is None else normalize_percent_encoding(normalized_fragment),
        query_pairs=tuple(query_pairs),
    )


def parse_netloc(netloc: str, *, require_host: bool = False) -> tuple[str | None, str | None, int | None]:
    """Parse ``userinfo@host:port`` into its three parts, exactly as an authority is parsed."""
    userinfo, host_candidate = parse_userinfo(netloc)
    host, port = parse_host(host_candidate, require_host=require_host)
    return userinfo, host, apply_port_defaults(None, port, host)


class Parser:
    """Stateful wrapper around :func:`parse_url`, kept for backward compatibility.

    ``URL`` no longer reads anything back off a parser instance; the module
    functions are what the package itself uses. Passing a ``Parser`` to
    ``URL(parser=...)`` is deprecated -- use ``allow_custom_scheme=``.
    """

    __slots__ = ("_custom_scheme", "_port", "_query_pairs", "_recognized_scheme")

    def __init__(self) -> None:
        self._custom_scheme = False
        self._recognized_scheme: bool | None = None
        self._query_pairs: QueryPairs = []
        self._port: int | None = None

    @property
    def custom_scheme(self) -> bool:
        return self._custom_scheme

    @custom_scheme.setter
    def custom_scheme(self, value: bool) -> None:
        self._custom_scheme = value

    @property
    def recognized_scheme(self) -> bool | None:
        return self._recognized_scheme

    @property
    def query_pairs(self) -> QueryPairs:
        return self._query_pairs

    @property
    def port(self) -> int | None:
        return self._port

    def parse(self, maybe_url: str) -> dict[str, Any | None]:
        """Parse a URL string into its components."""
        result = parse_url(maybe_url, allow_custom_scheme=self._custom_scheme)
        self._recognized_scheme = result.recognized_scheme
        self._query_pairs = list(result.query_pairs)
        self._port = result.port
        # Everything a caller needs travels in the return value. URL used to
        # read query_pairs/recognized_scheme back off this instance after the
        # call, so a Parser shared between threads handed one URL the query
        # pairs of another thread's parse.
        components = result.to_dict()
        components["query_pairs"] = list(result.query_pairs)
        components["recognized_scheme"] = result.recognized_scheme
        return components

    def parse_netloc(self, netloc: str, *, require_host: bool = False) -> tuple[str | None, str | None, int | None]:
        """Parse a netloc string into userinfo, host, and port."""
        return parse_netloc(netloc, require_host=require_host)


def get_cache_info() -> dict:
    """Statistics for the parser caches (path, host and percent-encoding normalization)."""
    return cache_info("parser")


def clear_caches() -> dict:
    """Clear the parser caches and return their previous sizes."""
    return clear_registered_caches("parser")


__all__ = [
    "Parser",
    "clear_caches",
    "get_cache_info",
    "normalize_components",
    "normalize_path",
    "parse_fragment_string",
    "parse_host",
    "parse_netloc",
    "parse_query_string",
    "parse_scheme",
    "parse_url",
    "parse_userinfo",
]
