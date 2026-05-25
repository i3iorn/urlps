from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Optional, Set
from urllib import request
from urllib.error import URLError

from .._patterns import PATTERNS
from ..constants import DEFAULT_DNS_TIMEOUT, PHISHING_DATABASE_URL
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

    # ---------------------------- Public API ---------------------------- #

    def check(self, host: str) -> bool:
        """Return True if host is present in the phishing database."""
        if not isinstance(host, str):
            return False

        normalized = host.lower().rstrip(".")
        if not normalized:
            return False

        if not self._db.hostnames:
            self.refresh()

        return normalized in self._db.hostnames

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

    # ---------------------------- Internal ----------------------------- #

    def _download(self) -> PhishingDatabase:
        """Download and validate phishing hostnames."""
        error_count = self._db.error_count

        try:
            with request.urlopen(
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

                raw_bytes = response.read()
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


def refresh_phishing_db() -> int:
    """Refresh phishing database and return item count."""
    return _GLOBAL_MANAGER.refresh()


def get_phishing_db_info() -> dict:
    """Return phishing database metadata."""
    return _GLOBAL_MANAGER.info()


__all__ = [
    "PhishingDatabase",
    "PhishingDatabaseManager",
    "check_against_phishing_db",
    "refresh_phishing_db",
    "get_phishing_db_info",
]

