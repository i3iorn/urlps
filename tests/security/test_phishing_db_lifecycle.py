"""Phishing database: refresh TTL, keep-on-failure, parent-domain matching, hash pin, fail-closed.

A list loaded once used to be kept for the life of the process; a failed
refresh replaced a working list with an empty one; only exact hostnames
matched, so subdomains of listed domains passed; an unreachable feed could
only ever produce a warning; and nothing checked the feed's integrity.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from urlps import InvalidURLError, PhishingDatabaseManager, PhishingFeedConfig, SecurityPolicy, parse_url
from urlps._security import phishing_db
from urlps._security.phishing_db import (
    check_against_phishing_db,
    check_against_phishing_db_detailed,
    clear_phishing_db,
    get_phishing_db_info,
    refresh_phishing_db,
)

URLOPEN = "urlps._security.phishing_db.request.urlopen"
FEED = b"evil.example\nphish.bad\nonly.sub.example\n203.0.113.9\n"


def _response(body: bytes = FEED, status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status = status
    response.read.return_value = body
    context = MagicMock()
    context.__enter__.return_value = response
    return context


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture(autouse=True)
def _fresh_db():
    clear_phishing_db()
    yield
    clear_phishing_db()


@pytest.fixture
def clock():
    fake = Clock()
    with patch("urlps._security.phishing_db.time.time", fake):
        yield fake


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host,listed",
    [
        ("evil.example", True),
        ("login.evil.example", True),
        ("a.b.c.evil.example", True),
        ("EVIL.example.", True),
        ("notevil.example", False),  # a suffix match must fall on a label boundary
        ("example", False),  # parents stop at two labels, never a bare TLD
        ("sub.example", False),
        ("x.only.sub.example", True),
        ("203.0.113.9", True),
        ("1.203.0.113.9", False),  # IP literals match exactly, not by "parent"
    ],
)
def test_listed_domains_match_with_their_subdomains(host: str, listed: bool) -> None:
    with patch(URLOPEN, return_value=_response()):
        assert check_against_phishing_db(host) is listed


def test_a_subdomain_of_a_listed_domain_is_rejected_end_to_end() -> None:
    with patch(URLOPEN, return_value=_response()):
        with pytest.raises(InvalidURLError) as excinfo:
            parse_url("https://login.evil.example/account", check_phishing=True)
    assert excinfo.value.code is not None and excinfo.value.code.value == "phishing_domain"


# ---------------------------------------------------------------------------
# Refresh lifecycle
# ---------------------------------------------------------------------------


def test_loaded_list_is_refreshed_after_its_ttl(clock: Clock) -> None:
    with patch(URLOPEN, return_value=_response(b"old.example\n")) as urlopen:
        assert check_against_phishing_db("old.example")
        clock.now += phishing_db.DEFAULT_PHISHING_DATABASE_REFRESH_SECONDS - 1
        check_against_phishing_db("old.example")
        assert urlopen.call_count == 1
    clock.now += 2
    with patch(URLOPEN, return_value=_response(b"new.example\n")) as urlopen:
        assert check_against_phishing_db("new.example")
        assert not check_against_phishing_db("old.example")
        assert urlopen.call_count == 1
    assert get_phishing_db_info()["stale"] is False


def test_failed_refresh_keeps_the_previous_list(clock: Clock) -> None:
    with patch(URLOPEN, return_value=_response()):
        assert check_against_phishing_db("evil.example")
    clock.now += phishing_db.DEFAULT_PHISHING_DATABASE_REFRESH_SECONDS + 1
    with patch(URLOPEN, side_effect=OSError("feed down")):
        assert check_against_phishing_db("evil.example") is True
        assert check_against_phishing_db_detailed("evil.example") == (True, True)
    info = get_phishing_db_info()
    assert info["loaded"] is True
    assert info["stale"] is True
    assert info["last_error"] == "download_error:OSError"


def test_failed_refresh_waits_out_the_cooldown(clock: Clock) -> None:
    with patch(URLOPEN, side_effect=OSError("feed down")) as urlopen:
        for _ in range(5):
            check_against_phishing_db("anything.example")
        assert urlopen.call_count == 1
        clock.now += phishing_db.DEFAULT_PHISHING_DATABASE_RETRY_COOLDOWN_SECONDS + 1
        check_against_phishing_db("anything.example")
        assert urlopen.call_count == 2


def test_explicit_refresh_failure_with_nothing_loaded_reports_zero() -> None:
    with patch(URLOPEN, side_effect=OSError("fail")):
        assert refresh_phishing_db() == 0
    assert get_phishing_db_info()["loaded"] is False


# ---------------------------------------------------------------------------
# Integrity pin
# ---------------------------------------------------------------------------


def test_pinned_hash_accepts_the_matching_feed() -> None:
    manager = PhishingDatabaseManager(PhishingFeedConfig(sha256=hashlib.sha256(FEED).hexdigest()))
    with patch(URLOPEN, return_value=_response()):
        assert manager.refresh() == 4
    assert manager.info()["sha256_pinned"] is True


def test_pinned_hash_rejects_a_tampered_feed() -> None:
    manager = PhishingDatabaseManager(PhishingFeedConfig(sha256=hashlib.sha256(FEED).hexdigest()))
    with patch(URLOPEN, return_value=_response(b"x.example\n")):
        assert manager.refresh() == 0
    assert manager.info()["last_error"] == "hash_mismatch"


def test_a_manager_can_be_pointed_anywhere_without_patching() -> None:
    """The feed's source, clock and limits are arguments now, not module globals."""
    fetched: list[tuple] = []

    def fetch(url: str, timeout: float, max_bytes: int) -> bytes:
        fetched.append((url, timeout, max_bytes))
        return b"evil.example\n"

    now = [1_000.0]
    manager = PhishingDatabaseManager(
        PhishingFeedConfig(url="https://mirror.internal/feed.txt", refresh_seconds=60, retry_cooldown_seconds=10),
        fetch=fetch,
        clock=lambda: now[0],
    )
    assert manager.lookup("login.evil.example") is True
    assert manager.lookup("good.example") is False
    assert fetched == [("https://mirror.internal/feed.txt", 2.0, 25 * 1024 * 1024)]
    now[0] += 61
    manager.lookup("good.example")
    assert len(fetched) == 2


def test_an_unloadable_feed_reports_nothing_checked() -> None:
    def fetch(url: str, timeout: float, max_bytes: int) -> bytes:
        raise OSError("unreachable")

    manager = PhishingDatabaseManager(fetch=fetch)
    assert manager.lookup("evil.example") is None
    assert manager.info()["last_error"] == "download_error:OSError"


@pytest.mark.parametrize("value,expected", [("A" * 64, "a" * 64), ("not-a-hash", "None"), ("", "None")])
def test_hash_pin_env_var_is_validated(value: str, expected: str) -> None:
    env = {**os.environ, "URLPS_PHISHING_DATABASE_SHA256": value}
    code = "import urlps.constants as c; print(c.PHISHING_DATABASE_SHA256)"
    result = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", code], env=env, capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == expected


# ---------------------------------------------------------------------------
# Fail-closed
# ---------------------------------------------------------------------------


def test_unavailable_database_is_a_warning_by_default() -> None:
    with patch(URLOPEN, side_effect=OSError("down")):
        url = parse_url("https://example.com/", check_phishing=True)
    assert [f.severity for f in url.security_findings if f.code == "phishing_db_unavailable"] == ["warning"]


@pytest.mark.parametrize("factory", ["strict", "balanced"])
def test_fail_closed_policy_rejects_when_the_database_is_unavailable(factory: str) -> None:
    policy = getattr(SecurityPolicy, factory)(check_phishing=True, phishing_fail_closed=True)
    with patch(URLOPEN, side_effect=OSError("down")), pytest.raises(InvalidURLError) as excinfo:
        parse_url("https://example.com/", policy=policy)
    assert excinfo.value.code is not None and excinfo.value.code.value == "phishing_db_unavailable"


def test_fail_closed_policy_accepts_clean_hosts_when_the_database_is_available() -> None:
    policy = SecurityPolicy.strict(check_phishing=True, phishing_fail_closed=True)
    with patch(URLOPEN, return_value=_response()):
        assert parse_url("https://example.com/", policy=policy).host == "example.com"
