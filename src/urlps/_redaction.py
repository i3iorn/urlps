"""Log-safe redaction of URLs and of the values exceptions carry.

A logging concern, not a threat check, so it lives apart from the security
heuristics and below everything that needs it (the security pass, audit,
URL). Everything here fails closed: when in doubt, mask.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .exceptions import URLpError

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


def redact_exception(exc: BaseException) -> None:
    """Redact, in place, the offending value an exception carries.

    ``str(exc)`` includes ``value``, and both end up in logs and error
    responses. Every public boundary (parsing, derivation, the security
    pass) calls this unless the caller asked for ``debug=True``.
    """
    if isinstance(exc, URLpError):
        exc.value = redact_component(exc.value, exc.component)


__all__ = [
    "REDACTED",
    "UNPARSEABLE_URL_PLACEHOLDER",
    "redact_component",
    "redact_exception",
    "redact_url_for_logs",
]
