"""URL string-level security checks and redaction helpers."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from functools import lru_cache
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlsplit, urlunparse, urlunsplit

from .._cache_config import SECURITY_CACHE_SIZE
from .._patterns import PATTERNS
from ..constants import DANGEROUS_PORTS

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


@lru_cache(maxsize=SECURITY_CACHE_SIZE)
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


@lru_cache(maxsize=SECURITY_CACHE_SIZE)
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


@lru_cache(maxsize=SECURITY_CACHE_SIZE)
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

    # The host/path split always needs both halves, so partition() once
    # (one scan) strictly beats an "x in s" pre-check plus split()/find()
    # (two-plus scans) for the same separator.
    host_portion, sep, rest = after_scheme.partition("/")
    path_portion = sep + rest

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


def is_dangerous_port(port: int | None, block_dangerous_ports: bool = False) -> bool:
    """Check if port is commonly exploited."""
    if not block_dangerous_ports or port is None:
        return False
    return port in DANGEROUS_PORTS


def normalize_url_unicode(url: str) -> str:
    """Normalize URL to NFC form to prevent normalization-based bypasses."""
    if not isinstance(url, str):
        return url
    try:
        return unicodedata.normalize("NFC", url)
    except (ValueError, TypeError):
        return url


def redact_url_for_logs(url: str) -> str:
    """Redact credentials and sensitive query values for logging/auditing."""
    if not isinstance(url, str) or not url:
        return url

    try:
        split = urlsplit(url)
        netloc = split.netloc
        if "@" in netloc:
            userinfo, _, host_part = netloc.rpartition("@")
            if ":" in userinfo:
                username, _, _ = userinfo.partition(":")
                netloc = f"{username}:***@{host_part}"
            else:
                netloc = f"***@{host_part}"

        query = split.query
        if query:
            redacted_pairs = []
            for key, value in parse_qsl(query, keep_blank_values=True):
                redacted_pairs.append((key, "***" if key.lower() in _SENSITIVE_QUERY_KEYS else value))
            query = urlencode(redacted_pairs, doseq=True)

        return urlunsplit((split.scheme, netloc, split.path, query, split.fragment))
    except (ValueError, AttributeError):
        return url


def has_suspicious_punycode(host: str) -> bool:
    """Detect suspicious Punycode/IDN domains with confusable characters."""
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
