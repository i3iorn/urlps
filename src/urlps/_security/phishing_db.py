"""The phishing-domain feed: download, verify, refresh and match.

``PhishingDatabaseManager`` takes its source (``fetch``), clock and limits
(``PhishingFeedConfig``) as arguments, so a deployment can point it at a
mirror or a local list and a test needs no monkeypatching. The module-level
functions use one process-global manager with the default configuration.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib import request
from urllib.error import URLError

from .._patterns import PATTERNS
from ..constants import (
    DEFAULT_PHISHING_DATABASE_MAX_BYTES,
    DEFAULT_PHISHING_DATABASE_REFRESH_SECONDS,
    DEFAULT_PHISHING_DATABASE_RETRY_COOLDOWN_SECONDS,
    DEFAULT_PHISHING_DATABASE_TIMEOUT_SECONDS,
    PHISHING_DATABASE_SHA256,
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

    hostnames: set[str] = field(default_factory=set)
    #: Last download *attempt*, successful or not (drives the retry cooldown).
    last_refresh_epoch: float | None = None
    last_error: str | None = None
    error_count: int = 0
    #: Last *successful* download (drives the refresh TTL).
    last_success_epoch: float | None = None


@dataclass(frozen=True)
class PhishingFeedConfig:
    """Where the feed comes from and how it is kept fresh."""

    url: str = PHISHING_DATABASE_URL
    timeout_seconds: float = DEFAULT_PHISHING_DATABASE_TIMEOUT_SECONDS
    max_bytes: int = DEFAULT_PHISHING_DATABASE_MAX_BYTES
    #: Re-download a successfully loaded list after this long.
    refresh_seconds: float = DEFAULT_PHISHING_DATABASE_REFRESH_SECONDS
    #: Never attempt a lazy download more often than this, success or not.
    retry_cooldown_seconds: float = DEFAULT_PHISHING_DATABASE_RETRY_COOLDOWN_SECONDS
    #: Reject a download whose SHA-256 differs (None: no pin).
    sha256: str | None = PHISHING_DATABASE_SHA256


def _wall_clock() -> float:
    # Looked up at call time, so substituting time.time still takes effect.
    return time.time()


class FeedUnavailable(Exception):
    """A fetch did not produce a feed; the message is the recorded reason."""


#: (url, timeout_seconds, max_bytes) -> the feed body. Raises FeedUnavailable
#: (or an OSError/ValueError) when there is nothing to load.
Fetch = Callable[[str, float, int], bytes]


def fetch_over_http(url: str, timeout_seconds: float, max_bytes: int) -> bytes:
    """Download the feed with urllib, refusing a non-200 answer or more than ``max_bytes``."""
    with request.urlopen(  # nosec B310 -- the configured feed URL, an https:// constant by default
        url,
        timeout=timeout_seconds,
    ) as response:
        if response.status != 200:
            raise FeedUnavailable(f"unexpected_status:{response.status}")
        body = response.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise FeedUnavailable("download_too_large")
    return bytes(body)


# ---------------------------------------------------------------------------
# Core Manager
# ---------------------------------------------------------------------------


class PhishingDatabaseManager:
    """Manages secure retrieval and caching of phishing hostnames.

    Implements the ``PhishingFeed`` interface (:meth:`lookup`) the security
    checks use.
    """

    def __init__(
        self,
        config: PhishingFeedConfig | None = None,
        *,
        fetch: Fetch = fetch_over_http,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._config = config if config is not None else PhishingFeedConfig()
        self._fetch = fetch
        self._clock = clock if clock is not None else _wall_clock
        self._db: PhishingDatabase = PhishingDatabase()
        # Serialises the lazy refresh. Without it, every thread that arrives
        # while the database is empty starts its own multi-megabyte download.
        self._refresh_lock = threading.Lock()

    # ---------------------------- Public API ---------------------------- #

    @property
    def is_available(self) -> bool:
        """Whether the database holds data, i.e. whether checks are meaningful."""
        return bool(self._db.hostnames)

    def lookup(self, host: str) -> bool | None:
        """True if ``host`` (or a parent domain) is listed, False if not, None if nothing could be checked."""
        listed = self.check(host)
        if listed:
            return True
        return False if self.is_available else None

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

        if self._should_attempt_refresh():
            with self._refresh_lock:
                # Re-check inside the lock: another thread may have completed
                # the refresh while we waited.
                if self._should_attempt_refresh():
                    self.refresh()

        return _matches(normalized, self._db.hostnames)

    def _should_attempt_refresh(self) -> bool:
        """Return True if a lazy check() should (re)download the list now.

        Never within the retry cooldown of the last attempt: last_refresh_epoch
        is stamped on failed attempts too, so without it a lazy check() would
        re-download on every call while the feed stays unreachable. Otherwise,
        when nothing is loaded, or when the loaded list is older than the
        refresh TTL. Explicit refresh() calls (refresh_phishing_db()) are
        unaffected -- they always attempt.
        """
        now = self._clock()
        last_attempt = self._db.last_refresh_epoch
        if last_attempt is not None and (now - last_attempt) < self._config.retry_cooldown_seconds:
            return False
        if not self._db.hostnames:
            return True
        last_success = self._db.last_success_epoch
        return last_success is None or (now - last_success) >= self._config.refresh_seconds

    def refresh(self) -> int:
        """Refresh the phishing database and return the number of entries."""
        new_db = self._download()
        self._db = new_db
        return len(new_db.hostnames)

    def info(self) -> dict:
        """Return metadata about the current phishing database."""
        last_success = self._db.last_success_epoch
        return {
            "loaded": bool(self._db.hostnames),
            "size": len(self._db.hostnames),
            "last_refresh_epoch": self._db.last_refresh_epoch,
            "last_success_epoch": last_success,
            "stale": bool(self._db.hostnames)
            and (last_success is None or self._clock() - last_success >= self._config.refresh_seconds),
            "sha256_pinned": self._config.sha256 is not None,
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

    def _failed(self, reason: str) -> PhishingDatabase:
        """A failed refresh keeps whatever was loaded before.

        Replacing a working list with an empty one on a transient download
        error turned one network blip into no phishing protection at all
        until the next successful download.
        """
        return PhishingDatabase(
            hostnames=self._db.hostnames,
            last_refresh_epoch=self._clock(),
            last_error=reason,
            error_count=self._db.error_count + 1,
            last_success_epoch=self._db.last_success_epoch,
        )

    def _download(self) -> PhishingDatabase:
        """Fetch, verify and parse the feed; on any failure keep what was loaded."""
        config = self._config
        try:
            raw_bytes = self._fetch(config.url, config.timeout_seconds, config.max_bytes)
        except FeedUnavailable as exc:
            return self._failed(str(exc))
        except (TimeoutError, URLError, OSError, ValueError) as exc:
            return self._failed(f"download_error:{type(exc).__name__}")
        if len(raw_bytes) > config.max_bytes:
            return self._failed("download_too_large")
        if config.sha256 is not None and hashlib.sha256(raw_bytes).hexdigest() != config.sha256:
            return self._failed("hash_mismatch")
        content = raw_bytes.decode("utf-8", errors="ignore")

        hostnames = self._parse_hostnames(content)
        now = self._clock()
        return PhishingDatabase(
            hostnames=hostnames,
            last_refresh_epoch=now,
            last_error=None,
            error_count=self._db.error_count,
            last_success_epoch=now,
        )

    @staticmethod
    def _parse_hostnames(content: str) -> set[str]:
        """Parse and validate hostnames from downloaded content."""
        valid: set[str] = set()

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


def _matches(host: str, hostnames: set[str]) -> bool:
    """Whether ``host`` or one of its parent domains is listed.

    Feeds list the domain that hosts the phishing page, so a subdomain of a
    listed domain is just as malicious -- exact matching let "login.evil.example"
    through when "evil.example" was listed. Parents are checked down to two
    labels (never a bare TLD). IP literals only match exactly.
    """
    if host in hostnames:
        return True
    if _is_ip_literal(host):
        return False
    labels = host.split(".")
    parents = (".".join(labels[index:]) for index in range(1, len(labels) - 1))
    # A listed IP is not a domain: "1.203.0.113.9" is not "under" 203.0.113.9.
    return any(parent in hostnames and not _is_ip_literal(parent) for parent in parents)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


_GLOBAL_MANAGER = PhishingDatabaseManager()


def default_phishing_feed() -> PhishingDatabaseManager:
    """The process-global feed the module functions (and default services) use."""
    return _GLOBAL_MANAGER


def check_against_phishing_db(host: str) -> bool:
    """Check if host exists in the phishing database."""
    return _GLOBAL_MANAGER.check(host)


def check_against_phishing_db_detailed(host: str) -> tuple[bool, bool]:
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
    "FeedUnavailable",
    "PhishingDatabase",
    "PhishingDatabaseManager",
    "PhishingFeedConfig",
    "check_against_phishing_db",
    "check_against_phishing_db_detailed",
    "clear_phishing_db",
    "default_phishing_feed",
    "fetch_over_http",
    "get_phishing_db_info",
    "refresh_phishing_db",
]
