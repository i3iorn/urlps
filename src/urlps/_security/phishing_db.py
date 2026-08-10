from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, Set, Tuple
from urllib import request
from urllib.error import URLError

from .._patterns import PATTERNS
from ..constants import (
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_PHISHING_DATABASE_MAX_BYTES,
    DEFAULT_PHISHING_DATABASE_RETRY_COOLDOWN_SECONDS,
    PHISHING_DATABASE_URL,
)
from ..exceptions import PhishingDatabaseError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PhishingDatabase:
    """Immutable phishing database container."""
    hostnames: Set[str] = field(default_factory=set)
    last_refresh_epoch: Optional[float] = None
    last_error: Optional[str] = None
    error_count: int = 0


# ---------------------------------------------------------------------------
# Core Manager
# ---------------------------------------------------------------------------

class PhishingDatabaseManager:
    """Manages secure retrieval and caching of phishing hostnames."""

    def __init__(self) -> None:
        self._db: PhishingDatabase = PhishingDatabase()
        # Serialises the lazy refresh. Without it, every thread that arrives
        # while the database is empty starts its own multi-megabyte download.
        self._refresh_lock = threading.Lock()

    # ---------------------------- Public API ---------------------------- #

    @property
    def is_available(self) -> bool:
        """Whether the database holds data, i.e. whether checks are meaningful."""
        return bool(self._db.hostnames)

    def check(self, host: str) -> bool:
        """Return True if host is present in the phishing database.

        Returns False both when a host is genuinely absent and when the
        database could not be loaded. Callers that need to distinguish those
        cases must consult :attr:`is_available` -- see
        :func:`check_against_phishing_db_detailed`.
        """
        if not isinstance(host, str):
            return False

        normalized = host.lower().rstrip(".")
        if not normalized:
            return False

        if not self._db.hostnames and self._should_attempt_refresh():
            with self._refresh_lock:
                # Re-check inside the lock: another thread may have completed
                # the refresh while we waited.
                if not self._db.hostnames and self._should_attempt_refresh():
                    self.refresh()

        return normalized in self._db.hostnames

    def _should_attempt_refresh(self) -> bool:
        """Return True if enough time has passed to retry a lazy refresh.

        last_refresh_epoch is stamped on failed attempts too, so without this
        cooldown a lazy check() would re-download on every single call while
        the phishing feed stays unreachable (network outage, egress block,
        etc.), turning a hostname-set lookup into a blocking network call on
        every parse_url(..., check_phishing=True). Explicit refresh() calls
        (refresh_phishing_db()) are unaffected -- they always attempt.
        """
        last_attempt = self._db.last_refresh_epoch
        if last_attempt is None:
            return True
        return (time.time() - last_attempt) >= DEFAULT_PHISHING_DATABASE_RETRY_COOLDOWN_SECONDS

    def refresh(self) -> int:
        """Refresh the phishing database and return the number of entries."""
        new_db = self._download()
        self._db = new_db
        return len(new_db.hostnames)

    def info(self) -> dict:
        """Return metadata about the current phishing database."""
        return {
            "loaded": bool(self._db.hostnames),
            "size": len(self._db.hostnames),
            "last_refresh_epoch": self._db.last_refresh_epoch,
            "last_error": self._db.last_error,
            "error_count": self._db.error_count,
        }

    def clear(self) -> None:
        """Clear the phishing database."""
        self._db = PhishingDatabase(
            hostnames=set(),
            last_refresh_epoch=None,
            last_error=None,
            error_count=0,
        )


    # ---------------------------- Internal ----------------------------- #

    def _download(self) -> PhishingDatabase:
        """Download and validate phishing hostnames."""
        error_count = self._db.error_count

        try:
            with request.urlopen(  # nosec B310 -- PHISHING_DATABASE_URL is a fixed https:// constant, not user input
                PHISHING_DATABASE_URL,
                timeout=DEFAULT_DNS_TIMEOUT,
            ) as response:

                if response.status != 200:
                    return PhishingDatabase(
                        hostnames=set(),
                        last_refresh_epoch=time.time(),
                        last_error=f"unexpected_status:{response.status}",
                        error_count=error_count + 1,
                    )

                raw_bytes = response.read(DEFAULT_PHISHING_DATABASE_MAX_BYTES + 1)
                if len(raw_bytes) > DEFAULT_PHISHING_DATABASE_MAX_BYTES:
                    return PhishingDatabase(
                        hostnames=set(),
                        last_refresh_epoch=time.time(),
                        last_error="download_too_large",
                        error_count=error_count + 1,
                    )
                content = raw_bytes.decode("utf-8", errors="ignore")

        except (URLError, socket.timeout, OSError, ValueError) as exc:
            return PhishingDatabase(
                hostnames=set(),
                last_refresh_epoch=time.time(),
                last_error=f"download_error:{type(exc).__name__}",
                error_count=error_count + 1,
            )

        hostnames = self._parse_hostnames(content)

        return PhishingDatabase(
            hostnames=hostnames,
            last_refresh_epoch=time.time(),
            last_error=None,
            error_count=error_count,
        )

    @staticmethod
    def _parse_hostnames(content: str) -> Set[str]:
        """Parse and validate hostnames from downloaded content."""
        valid: Set[str] = set()

        for line in content.splitlines():
            candidate = line.strip().lower()

            if not candidate:
                continue

            if len(candidate) > 253:
                continue

            if not PATTERNS["host"].fullmatch(candidate):
                continue

            valid.add(candidate)

        if len(valid) > 5_000_000:
            raise PhishingDatabaseError("phishing_db_too_large")

        return valid


_GLOBAL_MANAGER = PhishingDatabaseManager()


def check_against_phishing_db(host: str) -> bool:
    """Check if host exists in the phishing database."""
    return _GLOBAL_MANAGER.check(host)


def check_against_phishing_db_detailed(host: str) -> Tuple[bool, bool]:
    """Return ``(is_phishing, database_available)``.

    ``check_against_phishing_db`` alone cannot distinguish "this host is not a
    known phishing domain" from "the database could not be downloaded, so
    nothing was actually checked". Opting into ``check_phishing=True`` and
    silently receiving no protection is the worst failure mode available, so
    callers get the availability flag and can surface it.
    """
    is_phishing = _GLOBAL_MANAGER.check(host)
    return is_phishing, _GLOBAL_MANAGER.is_available


def refresh_phishing_db() -> int:
    """Refresh phishing database and return item count."""
    return _GLOBAL_MANAGER.refresh()


def get_phishing_db_info() -> dict:
    """Return phishing database metadata."""
    return _GLOBAL_MANAGER.info()

def clear_phishing_db() -> None:
    """Clear phishing database."""
    _GLOBAL_MANAGER.clear()


__all__ = [
    "PhishingDatabase",
    "PhishingDatabaseManager",
    "check_against_phishing_db",
    "check_against_phishing_db_detailed",
    "clear_phishing_db",
    "get_phishing_db_info",
    "refresh_phishing_db"
]

