"""Phishing database download and cache helpers."""
from __future__ import annotations

import socket
import time
from typing import Any, Dict, Optional, Set
from urllib import request
from urllib.error import URLError

from .._patterns import PATTERNS
from ..constants import DEFAULT_DNS_TIMEOUT, PHISHING_DATABASE_URL

PHISHING_SET: Optional[Set[str]] = None
_PHISHING_META: Dict[str, Any] = {
    "loaded": False,
    "size": 0,
    "last_refresh_epoch": None,
    "last_error": None,
    "error_count": 0,
}


def check_against_phishing_db(host: str) -> bool:
    """Check if hostname is in known phishing database."""
    global PHISHING_SET

    if PHISHING_SET is None:
        PHISHING_SET = _download_phishing_db()
        current_set = PHISHING_SET if PHISHING_SET is not None else set()
        _PHISHING_META["loaded"] = True
        _PHISHING_META["size"] = len(current_set)
        _PHISHING_META["last_refresh_epoch"] = time.time()

    if not isinstance(host, str):
        return False

    return host.lower().rstrip(".") in (PHISHING_SET if PHISHING_SET is not None else set())


def refresh_phishing_db() -> int:
    """Refresh the phishing database cache and return host count."""
    global PHISHING_SET

    PHISHING_SET = _download_phishing_db()
    current_set = PHISHING_SET if PHISHING_SET is not None else set()
    _PHISHING_META["loaded"] = True
    _PHISHING_META["size"] = len(current_set)
    _PHISHING_META["last_refresh_epoch"] = time.time()
    return len(current_set)


def get_phishing_db_info() -> dict:
    """Get information about the current phishing database cache."""
    return {
        "loaded": PHISHING_SET is not None,
        "size": len(PHISHING_SET) if PHISHING_SET is not None else 0,
        "last_refresh_epoch": _PHISHING_META.get("last_refresh_epoch"),
        "last_error": _PHISHING_META.get("last_error"),
        "error_count": int(_PHISHING_META.get("error_count", 0)),
    }


def _download_phishing_db() -> Set[str]:
    """Download and return a set of known phishing hostnames."""
    try:
        with request.urlopen(PHISHING_DATABASE_URL, timeout=DEFAULT_DNS_TIMEOUT) as response:
            if response.status != 200:
                _PHISHING_META["last_error"] = f"unexpected_status:{response.status}"
                _PHISHING_META["error_count"] = int(_PHISHING_META.get("error_count", 0)) + 1
                return set()

            print(response.read())

            content = response.read().decode("utf-8", errors="ignore")
            print(content)

        hostnames: Set[str] = set()
        for line in content.splitlines():
            candidate = line.strip().lower()
            if not candidate or len(candidate) > 253:
                continue
            if not PATTERNS["host"].fullmatch(candidate):
                continue
            hostnames.add(candidate)

        if len(hostnames) > 5_000_000:
            _PHISHING_META["last_error"] = "phishing_db_too_large"
            _PHISHING_META["error_count"] = int(_PHISHING_META.get("error_count", 0)) + 1
            return set()

        _PHISHING_META["last_error"] = None
        return hostnames
    except (URLError, socket.timeout, OSError, ValueError) as exc:
        _PHISHING_META["last_error"] = f"download_error:{type(exc).__name__}"
        _PHISHING_META["error_count"] = int(_PHISHING_META.get("error_count", 0)) + 1
        return set()

