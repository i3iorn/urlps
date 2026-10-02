"""URL string-level security checks and redaction helpers."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
import warnings
from collections.abc import Iterable
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlsplit, urlunparse, urlunsplit

from .._cache_config import SECURITY_CACHE_SIZE, bounded_lru_cache
from .._patterns import PATTERNS
from ..constants import DANGEROUS_PORTS

#: A query/fragment key is sensitive when, lowercased and stripped of "-",
#: "_" and ".", it *contains* one of these. Matching by substring is
#: deliberately broad: an exact list missed client_secret, id_token, code,
#: sig/X-Amz-Signature, session ids and API keys spelled any other way, and
#: over-redacting a log line ("keyword", "zipcode") costs nothing.
_SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "token",
    "secret",
    "key",
    "sig",
    "pass",
    "pwd",
    "auth",
    "session",
    "sid",
    "code",
    "credential",
    "jwt",
    "otp",
    "nonce",
    "cookie",
    "assertion",
    "saml",
    "ticket",
)

#: Kept for backward compatibility; every one of these is still redacted.
_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "apikey",
        "api_key",
        "password",
        "passwd",
        "secret",
        "auth",
        "authorization",
    }
)

#: What a URL that cannot even be split is logged as. Returning the input
#: instead -- as this used to -- leaked exactly the malformed URLs (typos with
#: credentials in them) that most often end up in error logs.
UNPARSEABLE_URL_PLACEHOLDER = "[unparseable URL redacted]"

REDACTED = "***"

#: "user:password@" anywhere in a string, for inputs urlsplit() does not see
#: an authority in ("https:/user:pw@host", "user:pw@host/path").
_USERINFO_LIKE = re.compile(r"(?P<user>[^\s/?#@:]+):(?P<password>[^\s/?#@]+)@")

_TRACKED_UNICODE_SCRIPTS = frozenset(
    {
        "LATIN",
        "CYRILLIC",
        "GREEK",
        "ARMENIAN",
        "HEBREW",
        "ARABIC",
        "THAI",
        "HANGUL",
        "HIRAGANA",
        "KATAKANA",
        "CJK",
    }
)


@bounded_lru_cache(maxsize=SECURITY_CACHE_SIZE, group="security")
def find_authority_marker(url: str) -> int:
    """Return the index of a genuine scheme '://' authority marker, or -1.

    A '://' only counts as a real scheme separator when nothing before it
    contains a '/', '?', or '#'. Otherwise it is embedded content (e.g. a
    redirect target in a query value like '?next=http://host') on what is
    actually a scheme-less, relative reference -- not a real authority.

    Performance: cached since callers (has_parser_confusion,
    extract_host_and_path, has_scheme_authority) are all invoked on the same
    URL string within a single parse/validate cycle.
    """
    if not isinstance(url, str):
        return -1
    idx = url.find("://")
    if idx == -1:
        return -1
    prefix = url[:idx]
    if "/" in prefix or "?" in prefix or "#" in prefix:
        return -1
    return idx


def has_scheme_authority(url: str) -> bool:
    """Return True if url has a genuine scheme authority ('scheme://...') or is protocol-relative ('//...')."""
    if not isinstance(url, str):
        return False
    return find_authority_marker(url) != -1 or url.startswith("//")


@bounded_lru_cache(maxsize=SECURITY_CACHE_SIZE, group="security")
def has_mixed_scripts(host: str) -> bool:
    """Detect potential homograph attacks using mixed Unicode scripts."""
    if not isinstance(host, str):
        return False

    try:
        host.encode("ascii")
        return False
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass

    scripts: set[str] = set()
    try:
        for char in host:
            if char.isalpha():
                script = unicodedata.name(char, "").split(" ", 1)[0]
                if script in _TRACKED_UNICODE_SCRIPTS:
                    scripts.add(script)
        return len(scripts) > 1
    except (ValueError, KeyError):
        return False


def has_double_encoding(value: str) -> bool:
    """Detect potential double-encoding attacks."""
    if not isinstance(value, str):
        return False
    return bool(PATTERNS["double_encode"].search(value))


def has_path_traversal(path: str) -> bool:
    """Detect path traversal attempts (.., null bytes, encoded variants)."""
    if not isinstance(path, str):
        return False
    if ".." in path or "\x00" in path:
        return True
    try:
        decoded = unquote(path)
        if ".." in decoded or "\x00" in decoded:
            return True
        if ".." in unquote(decoded):
            return True
    except (ValueError, UnicodeDecodeError):
        return False
    return False


def is_open_redirect_risk(path: str) -> bool:
    """Check if path could cause an open redirect (//, backslash), including percent-encoded forms.

    A raw backslash or leading "//" is checked first since some clients
    (older IIS/browser combinations) treat a backslash as a path separator
    equivalent to "/". The same check is repeated against the percent-decoded
    form so an encoded backslash (e.g. "%5c") can't slip past by only ever
    appearing "safe" in its raw, still-encoded representation.
    """
    if not isinstance(path, str):
        return False
    if "\\" in path or path.startswith("//"):
        return True
    try:
        decoded = unquote(path)
    except (ValueError, UnicodeDecodeError):
        return False
    return "\\" in decoded or decoded.startswith("//")


def _has_mixed_path_separators(after_scheme: str) -> bool:
    return "/" in after_scheme and "\\" in after_scheme


def _has_slash_before_domain_dot(after_scheme: str) -> bool:
    slash_pos = after_scheme.find("/")
    dot_pos = after_scheme.find(".")
    return slash_pos != -1 and dot_pos != -1 and slash_pos < dot_pos


def _extract_authority_and_rest(after_scheme: str) -> tuple[str, str]:
    end = len(after_scheme)
    for terminator in ("/", "?", "#"):
        idx = after_scheme.find(terminator)
        if idx != -1:
            end = min(end, idx)
    return after_scheme[:end], after_scheme[end:]


def _has_component_ordering_confusion(rest: str) -> bool:
    if "#" in rest:
        slash_pos = rest.find("/")
        hash_pos = rest.find("#")
        if slash_pos != -1 and hash_pos < slash_pos:
            return True

    if "?" in rest:
        slash_pos = rest.find("/")
        query_pos = rest.find("?")
        if slash_pos != -1 and query_pos < slash_pos:
            return True

    return False


def _has_multiple_at_symbols(authority: str) -> bool:
    return authority.count("@") > 1


def _has_confusing_userinfo_markers(authority: str) -> bool:
    at_count = authority.count("@")
    if at_count == 0:
        return False
    before_last_at, _ = authority.rsplit("@", 1)
    return any(terminator in before_last_at for terminator in ("/", "?", "#"))


@bounded_lru_cache(maxsize=SECURITY_CACHE_SIZE, group="security")
def has_parser_confusion(url: str) -> bool:
    """Detect ambiguous URLs that could be parsed differently by different parsers.

    Performance: cached because URL.__init__ calls this once as a pre-check
    and once again as part of full security-finding collection for the same
    string.
    """
    marker = find_authority_marker(url)
    if marker == -1:
        return False

    after_scheme = url[marker + 3 :]

    # Cheap guards ahead of the helper cascade below: "\\" and "@" are each
    # checked by two of the helpers, so a single membership test up front
    # lets the overwhelmingly common case (neither character present) skip
    # straight past both pairs instead of calling into each one to find out.
    has_backslash = "\\" in after_scheme

    if has_backslash and _has_mixed_path_separators(after_scheme):
        return True
    if _has_slash_before_domain_dot(after_scheme):
        return True

    authority, rest = _extract_authority_and_rest(after_scheme)
    if _has_component_ordering_confusion(rest):
        return True

    if not authority:
        return False
    if has_backslash and "\\" in authority:
        return True
    if "@" in authority:
        if _has_multiple_at_symbols(authority):
            return True
        if _has_confusing_userinfo_markers(authority):
            return True

    return False


def has_credentials(url: str) -> bool:
    """Detect URLs containing credentials (userinfo) in authority."""
    if not isinstance(url, str):
        return False
    if not url:
        return False

    try:
        parsed = urlsplit(url)
    except ValueError:
        return False

    # urlsplit() populates netloc for both absolute and scheme-relative URLs.
    return "@" in parsed.netloc


def extract_host_and_path(url: str) -> tuple[str, str]:
    """Extract host and path portions from URL for security checks."""
    marker = find_authority_marker(url)
    if marker != -1:
        after_scheme = url[marker + 3 :]
    elif url.startswith("//"):
        after_scheme = url[2:]
    else:
        return "", ""

    # The authority ends at the first "/", "?" or "#" (RFC 3986 §3.2), not
    # just at "/". Splitting on "/" alone read "http://127.0.0.1?x" as host
    # "127.0.0.1?x" -- not an IP, so the SSRF check passed -- while the
    # parser (which splits off "#" and "?" first) produced host "127.0.0.1".
    host_portion, rest = _extract_authority_and_rest(after_scheme)
    path_portion = rest if rest.startswith("/") else ""

    # Userinfo and explicit ports are the exception rather than the rule, so
    # keep the cheap "x in s" pre-check here: it lets the common case (no
    # "@"/":") skip straight past without paying for a partition() call and
    # tuple allocation that would just be discarded.
    if "@" in host_portion:
        host_portion = host_portion.split("@", 1)[1]

    if ":" in host_portion and not host_portion.startswith("["):
        host_portion = host_portion.split(":", 1)[0]
    elif host_portion.startswith("[") and "]:" in host_portion:
        host_portion = host_portion.split("]:", 1)[0] + "]"

    if path_portion:
        path_portion = path_portion.split("?", 1)[0].split("#", 1)[0]

    return host_portion, path_portion


def is_commonly_abused_port(port: int | None) -> bool:
    """Whether ``port`` is one commonly abused for SSRF / protocol smuggling (SSH, SMTP, databases...)."""
    return port is not None and port in DANGEROUS_PORTS


def is_dangerous_port(port: int | None, block_dangerous_ports: bool = False) -> bool:
    """Compatibility wrapper: :func:`is_commonly_abused_port`, gated by a flag.

    The flag duplicated the policy's own ``block_dangerous_ports``; the
    security checks now ask the policy and call the plain predicate.
    """
    return block_dangerous_ports and is_commonly_abused_port(port)


def normalize_url_unicode(url: str) -> str:
    """Normalize URL to NFC form to prevent normalization-based bypasses."""
    if not isinstance(url, str):
        return url
    try:
        return unicodedata.normalize("NFC", url)
    except (ValueError, TypeError):
        return url


def _is_sensitive_key(key: str, extra: Iterable[str] = ()) -> bool:
    folded = key.lower().replace("-", "").replace("_", "").replace(".", "")
    if not folded.strip():
        return True  # a value with no name ("?=x") gives no reason to believe it is safe to log
    return any(part in folded for part in (*_SENSITIVE_KEY_PARTS, *extra)) or key.lower() in _SENSITIVE_QUERY_KEYS


def _redact_pairs(text: str, *, all_values: bool, extra: Iterable[str] = ()) -> str:
    """Mask the values of sensitive ``key=value`` pairs (every value if ``all_values``)."""
    redacted_pairs = []
    for key, value in parse_qsl(text, keep_blank_values=True):
        redacted_pairs.append((key, REDACTED if all_values or _is_sensitive_key(key, extra) else value))
    return urlencode(redacted_pairs, doseq=True)


def _redact_userinfo(userinfo: str) -> str:
    """``user:password`` -> ``user:***``; a bare token (no ":") -> ``***``."""
    if ":" in userinfo:
        username, _, _ = userinfo.partition(":")
        return f"{username}:{REDACTED}"
    return REDACTED


def redact_url_for_logs(url: str, *, extra_sensitive_keys: Iterable[str] = ()) -> str:
    """Redact credentials and sensitive query/fragment values for logging/auditing.

    - Userinfo: the password (or a bare token) is masked.
    - Query: values of sensitive keys are masked (see ``_SENSITIVE_KEY_PARTS``;
      ``extra_sensitive_keys`` adds more substrings).
    - Fragment: every ``key=value`` value is masked -- fragments carry OAuth
      implicit-flow tokens and are never sent to a server, so their values
      have no debugging use. A plain anchor (``#section``) is kept.
    - Fails closed: a URL that cannot be split is replaced by
      ``UNPARSEABLE_URL_PLACEHOLDER``, never returned as-is.
    """
    if not isinstance(url, str) or not url:
        return url
    extra = tuple(part.lower().replace("-", "").replace("_", "").replace(".", "") for part in extra_sensitive_keys)

    try:
        split = urlsplit(url)
        netloc = split.netloc
        if "@" in netloc:
            userinfo, _, host_part = netloc.rpartition("@")
            netloc = f"{_redact_userinfo(userinfo)}@{host_part}"

        query = _redact_pairs(split.query, all_values=False, extra=extra) if split.query else split.query
        fragment = split.fragment
        if fragment and "=" in fragment:
            fragment = _redact_pairs(fragment, all_values=True)

        redacted = urlunsplit((split.scheme, netloc, split.path, query, fragment))
    except (ValueError, AttributeError):
        return UNPARSEABLE_URL_PLACEHOLDER
    # Credentials urlsplit did not recognise as an authority.
    return _USERINFO_LIKE.sub(lambda m: f"{m.group('user')}:{REDACTED}@", redacted)


def redact_component(value: object, component: str | None) -> object:
    """Redact an exception's offending ``value`` according to which component it is.

    Exceptions carry the input that failed, and both ``str(exc)`` and
    ``exc.value`` routinely end up in logs and error responses.
    """
    if not isinstance(value, str) or not value:
        return value
    if component == "userinfo":
        return _redact_userinfo(value)
    if component == "query":
        # Every value: the query failed to parse, so key names are no guide
        # ("?=SECRET" has no key at all).
        try:
            return _redact_pairs(value, all_values=True)
        except ValueError:
            return REDACTED
    if component == "fragment":
        return _redact_pairs(value, all_values=True) if "=" in value else value
    if "@" in value or "?" in value or "#" in value or "://" in value or value.startswith("//"):
        return redact_url_for_logs(value)
    return value


def has_suspicious_punycode(host: str) -> bool:
    """Detect suspicious Punycode/IDN domains with confusable characters.

    .. deprecated::
        This predates and is superseded by the real UTS-39 script/confusable
        analysis in ``host_analysis.analyze_host`` (what ``parse_url()``
        actually enforces via ``enforce_mixed_scripts``/
        ``enforce_confusable_host``). Its own heuristics here (hardcoded
        suspicious-TLD and brand-name lists, ad hoc substring checks) are
        weaker and unmaintained. Will be removed in a future major release.
    """
    warnings.warn(
        "has_suspicious_punycode() is deprecated and uses weaker, unmaintained "
        "heuristics than parse_url()'s actual homograph detection; use "
        "urlps._security.host_analysis.analyze_host() instead. This function "
        "will be removed in a future major release.",
        DeprecationWarning,
        stacklevel=2,
    )
    if not isinstance(host, str) or not host:
        return False

    host_lower = host.lower()
    is_punycode = "xn--" in host_lower

    decoded_host = host_lower
    if is_punycode:
        try:
            labels = host_lower.split(".")
            decoded_labels = []
            for label in labels:
                if label.startswith("xn--"):
                    try:
                        decoded_labels.append(label.encode("ascii").decode("idna"))
                    except (UnicodeError, UnicodeDecodeError):
                        decoded_labels.append(label)
                else:
                    decoded_labels.append(label)
            decoded_host = ".".join(decoded_labels)
        except (UnicodeError, UnicodeDecodeError, ValueError):
            return True

    if has_mixed_scripts(decoded_host):
        return True

    parts = decoded_host.split(".")
    if len(parts) < 2:
        return False

    tld = parts[-1]
    domain = parts[-2] if len(parts) >= 2 else ""

    suspicious_tlds = {
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "pw",
        "top",
        "work",
        "click",
        "link",
        "xyz",
        "loan",
        "win",
        "bid",
        "racing",
        "download",
        "stream",
        "science",
        "accountant",
    }
    if is_punycode and tld in suspicious_tlds:
        return True

    confusable_pairs = ["rn", "vv", "cl", "l1", "0o"]
    if any(pair in domain for pair in confusable_pairs):
        return True

    if domain.count("-") > 2:
        return True

    has_digits = any(c.isdigit() for c in domain)
    has_non_ascii = False
    try:
        domain.encode("ascii")
    except (UnicodeEncodeError, UnicodeDecodeError):
        has_non_ascii = True

    if has_digits and has_non_ascii:
        return True

    if has_non_ascii:
        domain_no_punct = domain.replace("-", "").replace("_", "")
        if domain_no_punct and all(c.isdigit() for c in domain_no_punct if c.isalnum()):
            return True

    common_brands = [
        "paypal",
        "google",
        "amazon",
        "apple",
        "microsoft",
        "facebook",
        "twitter",
        "instagram",
        "netflix",
        "ebay",
        "bank",
        "secure",
        "login",
        "account",
        "verify",
    ]
    if has_non_ascii and any(brand in decoded_host for brand in common_brands):
        return True

    return False


def get_canonical_url(url: str) -> str | None:
    """Convert URL to canonical form."""
    if not isinstance(url, str) or not url or find_authority_marker(url) == -1:
        return None

    try:
        from posixpath import normpath

        parsed = urlparse(url)
        scheme = parsed.scheme.lower() if parsed.scheme else ""

        netloc = parsed.netloc
        if netloc:
            userinfo = ""
            port = parsed.port

            if "@" in netloc:
                userinfo_part, netloc_without_userinfo = netloc.rsplit("@", 1)
                userinfo = userinfo_part + "@"
            else:
                netloc_without_userinfo = netloc

            if netloc_without_userinfo.startswith("["):
                if "]:" in netloc_without_userinfo:
                    host = netloc_without_userinfo.split("]:")[0] + "]"
                elif netloc_without_userinfo.endswith("]"):
                    host = netloc_without_userinfo
                else:
                    host = f"[{parsed.hostname}]" if parsed.hostname else ""
            else:
                host = parsed.hostname or ""
                if ":" in netloc_without_userinfo and not netloc_without_userinfo.startswith("["):
                    host = netloc_without_userinfo.split(":", 1)[0]

            host = host.lower()
            if host.endswith(".") and host != ".":
                host = host[:-1]

            if host.startswith("[") and host.endswith("]"):
                try:
                    ipv6_str = host[1:-1]
                    zone_id = ""
                    if "%" in ipv6_str:
                        ipv6_str, zone_id = ipv6_str.split("%", 1)
                        zone_id = "%" + zone_id
                    host = f"[{ipaddress.IPv6Address(ipv6_str)}{zone_id}]"
                except ValueError:
                    pass

            if port:
                default_ports = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}
                if scheme in default_ports and port == default_ports[scheme]:
                    port = None

            netloc = f"{userinfo}{host}:{port}" if port else f"{userinfo}{host}"

        path = parsed.path
        if path:
            path = normpath(path)

            def replace_percent(match: re.Match[str]) -> str:
                hex_val = match.group(1)
                char = chr(int(hex_val, 16))
                if char.isalnum() or char in "-._~":
                    return char
                return f"%{hex_val.upper()}"

            path = re.sub(r"%([0-9A-Fa-f]{2})", replace_percent, path)

        query = parsed.query
        if query:
            query = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: f"%{m.group(1).upper()}", query)

        fragment = parsed.fragment
        if fragment:
            fragment = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: f"%{m.group(1).upper()}", fragment)

        return urlunparse((scheme, netloc, path, parsed.params, query, fragment))
    except (ValueError, AttributeError):
        return None
