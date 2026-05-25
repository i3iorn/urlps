"""URL string-level security checks and redaction helpers."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from functools import lru_cache
from typing import Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit, urlparse, urlunparse

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


@lru_cache(maxsize=512)
def has_mixed_scripts(host: str) -> bool:
    """Detect potential homograph attacks using mixed Unicode scripts."""
    if not isinstance(host, str):
        return False

    try:
        host.encode("ascii")
        return False
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass

    scripts: Set[str] = set()
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
    """Check if path could cause an open redirect (//, backslash)."""
    if not isinstance(path, str):
        return False
    return "\\" in path or path.startswith("//")


def _has_mixed_path_separators(after_scheme: str) -> bool:
    return "/" in after_scheme and "\\" in after_scheme


def _has_slash_before_domain_dot(after_scheme: str) -> bool:
    slash_pos = after_scheme.find("/")
    dot_pos = after_scheme.find(".")
    return slash_pos != -1 and dot_pos != -1 and slash_pos < dot_pos


def _extract_authority_and_rest(after_scheme: str) -> Tuple[str, str]:
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


def has_parser_confusion(url: str) -> bool:
    """Detect ambiguous URLs that could be parsed differently by different parsers."""
    if not isinstance(url, str) or "://" not in url:
        return False

    after_scheme = url.split("://", 1)[1]

    if _has_mixed_path_separators(after_scheme):
        return True
    if _has_slash_before_domain_dot(after_scheme):
        return True

    authority, rest = _extract_authority_and_rest(after_scheme)
    if _has_component_ordering_confusion(rest):
        return True

    if not authority:
        return False
    if "\\" in authority:
        return True
    if _has_multiple_at_symbols(authority):
        return True
    if _has_confusing_userinfo_markers(authority):
        return True

    return False


def has_query_injection(query_string: str) -> bool:
    """Detect potential XSS/injection patterns in query strings."""
    if not isinstance(query_string, str) or not query_string:
        return False

    query_lower = query_string.lower()
    normalized_spaces = (
        query_lower.replace("%20", " ").replace("%09", " ").replace("%0a", " ")
    )
    query_normalized = " ".join(normalized_spaces.split())

    xss_patterns = [
        "<script",
        "</script",
        "javascript:",
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "<iframe",
        "<object",
        "<embed",
        "vbscript:",
        "data:text/html",
        "<img",
        "src=",
        "<body",
        "onfocus=",
        "onblur=",
        "<svg",
        "onanimation",
        "<input",
    ]
    sql_patterns = [
        "union select",
        "union all select",
        "' or '",
        '" or "',
        "' or 1=1",
        '" or 1=1',
        "' and '",
        '" and "',
        "' and 1=1",
        '" and 1=1',
        "drop table",
        "delete from",
        "insert into",
        "update set",
        "--",
        "/*",
        "*/",
        "exec(",
        "execute(",
        "xp_cmdshell",
        "sp_executesql",
        "sleep(",
        "waitfor",
        "benchmark(",
    ]
    cmd_patterns = [
        "$(",
        "`",
        "&&",
        "||",
        "; rm",
        ";rm ",
        ";cat ",
        "|cat",
        "|nc",
        "/bin/",
        "/etc/passwd",
        "/etc/shadow",
        "cmd.exe",
        "powershell",
    ]
    ldap_patterns = ["*)(", "(|", "(&", "(cn=*)"]
    xml_patterns = ["<!entity", "<!doctype", "<![cdata[", "<?xml"]
    traversal_patterns = ["../", "..\\", "%2e%2e/", "%2e%2e\\", "%2e%2e%2f", "%2e%2e%5c"]

    all_patterns = xss_patterns + sql_patterns + cmd_patterns + ldap_patterns + xml_patterns + traversal_patterns
    if any(pattern in query_lower or pattern in query_normalized for pattern in all_patterns):
        return True

    encoded_patterns = ["%3c", "%3e", "%27", "%22", "%3b", "%7c", "%26%26", "%7c%7c"]
    for pattern in encoded_patterns:
        if pattern not in query_lower:
            continue

        if pattern in ["%3c", "%3e"]:
            idx = query_lower.find(pattern)
            if idx != -1 and idx + len(pattern) < len(query_lower):
                following = query_lower[idx + len(pattern):idx + len(pattern) + 10]
                if any(kw in following for kw in ["script", "iframe", "object", "svg", "body", "img"]):
                    return True
        elif pattern in ["%27", "%22"]:
            idx = query_lower.find(pattern)
            if idx != -1:
                context = query_lower[max(0, idx - 10): min(len(query_lower), idx + 20)]
                if any(kw in context for kw in ["or", "and", "union", "select", "1=1"]):
                    return True
        else:
            return True

    return False


def has_credentials(url: str) -> bool:
    """Detect URLs containing credentials (userinfo) in authority."""
    if not isinstance(url, str):
        return False
    if "://" not in url:
        return False

    after_scheme = url.split("://", 1)[1]
    if "/" in after_scheme:
        authority = after_scheme.split("/", 1)[0]
    else:
        authority = after_scheme.split("?", 1)[0].split("#", 1)[0]

    return "@" in authority


def extract_host_and_path(url: str) -> Tuple[str, str]:
    """Extract host and path portions from URL for security checks."""
    if "://" in url:
        after_scheme = url.split("://", 1)[1]
    elif url.startswith("//"):
        after_scheme = url[2:]
    else:
        return "", ""

    if "/" in after_scheme:
        host_portion = after_scheme.split("/", 1)[0]
        path_portion = after_scheme[after_scheme.find("/"):]
    else:
        host_portion, path_portion = after_scheme, ""

    if "@" in host_portion:
        host_portion = host_portion.split("@", 1)[1]

    if ":" in host_portion and not host_portion.startswith("["):
        host_portion = host_portion.split(":", 1)[0]
    elif host_portion.startswith("[") and "]:" in host_portion:
        host_portion = host_portion.split("]:", 1)[0] + "]"

    if path_portion:
        path_portion = path_portion.split("?", 1)[0].split("#", 1)[0]

    return host_portion, path_portion


def is_dangerous_port(port: Optional[int], block_dangerous_ports: bool = False) -> bool:
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


def is_non_canonical_url(url: str) -> bool:
    """Detect URLs that are not in canonical form."""
    if not isinstance(url, str) or not url or "://" not in url:
        return False

    raw_host = ""
    try:
        from urllib.parse import urlparse

        scheme_end = url.find("://")
        if scheme_end > 0:
            raw_scheme = url[:scheme_end]
            if raw_scheme != raw_scheme.lower():
                return True

        parsed = urlparse(url)

        after_scheme = url.split("://", 1)[1]
        netloc_end = len(after_scheme)
        for char in ["/", "?", "#"]:
            pos = after_scheme.find(char)
            if pos != -1:
                netloc_end = min(netloc_end, pos)
        raw_netloc = after_scheme[:netloc_end]

        raw_host = raw_netloc
        if "@" in raw_host:
            raw_host = raw_host.split("@", 1)[1]
        if ":" in raw_host and not raw_host.startswith("["):
            raw_host = raw_host.split(":", 1)[0]
        elif raw_host.startswith("[") and "]:" in raw_host:
            raw_host = raw_host.split("]:")[0] + "]"

        if raw_host and raw_host != raw_host.lower():
            return True

        netloc = parsed.netloc
        if netloc:
            host_part = netloc.split(":")[0] if ":" in netloc else netloc
            if "@" in host_part:
                host_part = host_part.split("@", 1)[1]
            if host_part.endswith(".") and host_part != ".":
                return True

        if parsed.port:
            default_ports = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}
            if parsed.scheme.lower() in default_ports and parsed.port == default_ports[parsed.scheme.lower()]:
                return True

        path = parsed.path
        if path:
            if "/./" in path or path.startswith("./"):
                return True
            if "/../" in path or path.startswith("../"):
                return True
            if path.endswith("/.") or path.endswith("/.."):
                return True

            for hex_val in re.findall(r"%([0-9A-Fa-f]{2})", path):
                char = chr(int(hex_val, 16))
                if char.isalnum() or char in "-._~":
                    return True

            for part in re.findall(r"%[0-9A-Fa-f]{2}", path):
                if part != part.upper():
                    return True

        query = parsed.query
        if query:
            for part in re.findall(r"%[0-9A-Fa-f]{2}", query):
                if part != part.upper():
                    return True

        if raw_host and raw_host.startswith("[") and "]" in raw_host:
            try:
                bracket_end = raw_host.index("]")
                ipv6_str = raw_host[1:bracket_end]
                if "%" in ipv6_str:
                    ipv6_str = ipv6_str.split("%", 1)[0]
                canonical = str(ipaddress.IPv6Address(ipv6_str))
                if ipv6_str.lower() != canonical.lower():
                    return True
            except ValueError:
                pass

        fragment = parsed.fragment
        if fragment:
            for part in re.findall(r"%[0-9A-Fa-f]{2}", fragment):
                if part != part.upper():
                    return True

    except (ValueError, AttributeError):
        return False

    return False


def get_canonical_url(url: str) -> Optional[str]:
    """Convert URL to canonical form."""
    if not isinstance(url, str) or not url or "://" not in url:
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

