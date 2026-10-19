"""Bounds on the phishing feed download.

The feed download used to be one ``response.read(max_bytes)`` with a
per-operation socket timeout: a feed that trickles one byte just under the
timeout could keep that read -- and the refresh lock every
``check_phishing=True`` parse is queued behind -- alive indefinitely. It
now reads in chunks and enforces a total wall-clock deadline.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from urlps._security.phishing_db import (
    DEFAULT_PHISHING_DATABASE_DOWNLOAD_DEADLINE_SECONDS,
    FeedUnavailable,
    fetch_over_http,
)

URLOPEN = "urlps._security.phishing_db.request.urlopen"


class _FakeResponse:
    """A fake urlopen context: serves preloaded chunks, then EOF."""

    def __init__(self, chunks, read_sizes: list[int], status: int = 200) -> None:
        self.status = status
        self._chunks = list(chunks)
        self.read_sizes = read_sizes

    def read(self, size=-1) -> bytes:
        self.read_sizes.append(size)
        return self._chunks.pop(0) if self._chunks else b""


def _patched_urlopen(chunks, read_sizes: list[int], status: int = 200):
    def opener(*args, **kwargs):
        context = MagicMock()
        context.__enter__.return_value = _FakeResponse(chunks, read_sizes, status=status)
        return context

    return patch(URLOPEN, side_effect=opener)


class _AdvancingMonotonic:
    """time.monotonic patched to advance ``step`` seconds per call."""

    def __init__(self, step: float = 11.0) -> None:
        self.now = 0.0
        self.step = step

    def __call__(self) -> float:
        self.now += self.step
        return self.now


class TestDeadline:
    def test_trickling_feed_is_cut_off_by_the_deadline(self):
        # An 11s step crosses the 30s deadline on the third monotonic read;
        # the trickle itself never ends (100 chunks available).
        clock = _AdvancingMonotonic(step=11.0)
        patcher = _patched_urlopen([b"a" * 1024] * 100, [])
        with patcher, patch("urlps._security.phishing_db.time.monotonic", clock):
            with pytest.raises(FeedUnavailable, match="download_deadline_exceeded"):
                fetch_over_http("https://feed.example/x", 2.0, 25 * 1024 * 1024)

    def test_deadline_constant_is_finite(self):
        assert 0 < DEFAULT_PHISHING_DATABASE_DOWNLOAD_DEADLINE_SECONDS < 300.0

    def test_reads_are_chunked_not_one_giant_read(self):
        read_sizes: list[int] = []
        patcher = _patched_urlopen([b"evil.example", b"phish.bad", b""], read_sizes)
        with patcher, patch("urlps._security.phishing_db.time.monotonic", _AdvancingMonotonic(step=0.001)):
            body = fetch_over_http("https://feed.example/x", 2.0, 25 * 1024 * 1024)
        assert body == b"evil.examplephish.bad"
        # The old single read(max_bytes + 1) is gone: reads are bounded chunks.
        assert read_sizes and all(size <= 2 * 1024 * 1024 for size in read_sizes)


class TestSizeCap:
    def test_stream_larger_than_max_bytes_is_rejected(self):
        patcher = _patched_urlopen([b"a" * 8, b"b" * 8], [])
        with patcher, patch("urlps._security.phishing_db.time.monotonic", _AdvancingMonotonic(step=0.001)):
            with pytest.raises(FeedUnavailable, match="download_too_large"):
                fetch_over_http("https://feed.example/x", 2.0, 10)


class TestNon200:
    def test_unexpected_status_is_feed_unavailable(self):
        read_sizes: list[int] = []
        patcher = _patched_urlopen([b"should not be read"], read_sizes, status=500)
        with patcher, patch("urlps._security.phishing_db.time.monotonic", _AdvancingMonotonic(step=0.001)):
            with pytest.raises(FeedUnavailable, match="unexpected_status:500"):
                fetch_over_http("https://feed.example/x", 2.0, 25 * 1024 * 1024)
        assert not read_sizes  # failed at the status check, before any read
