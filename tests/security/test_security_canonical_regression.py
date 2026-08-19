"""
Non-bypass proof for the removal of ``require_canonical``.

Phase 2 of the 1.0 work deleted the ``require_canonical`` gate and replaced it
with unconditional normalization. That is only safe if **nothing** was relying
on the gate to block an attack. This file pins that claim down.

The argument, per sub-behavior of the old ``is_non_canonical_url``:

* uppercase scheme/host, default port, ``/./``, hex-escape case, over-encoded
  unreserved characters, non-canonical IPv6 -- all now *normalized*, so there
  is nothing left to reject and equal resources compare equal (covered by
  ``test_security_canonical.py``).
* ``/../`` -- the one sub-behavior with real security content, and it was
  never the canonical gate's job: ``enforce_path_traversal`` catches it
  independently. **That is what this file proves.**

If any assertion here starts failing, removing the gate opened a hole.
"""

from __future__ import annotations

import pytest

from urlps import InvalidURLError, parse_url
from urlps.exceptions import ErrorCode

ALL_POLICIES = ["strict", "balanced"]

#: Every one of these was blocked before the gate was removed and must still
#: be blocked after. `internal` is excluded deliberately -- it disables
#: enforce_path_traversal by design, which is a documented opt-out, not a
#: regression.
TRAVERSAL_VECTORS = [
    "https://example.com/a/../b",
    "https://example.com/../../etc/passwd",
    "https://example.com/a/../../../etc/passwd",
    "https://example.com/%2e%2e/x",
    "https://example.com/%2E%2E/x",
    "https://example.com/..%2fx",
    "https://example.com/....//....//etc/passwd",
    "https://example.com/path/%00.jpg/../../etc/passwd",
]

DOUBLE_ENCODED_VECTORS = [
    "https://example.com/%252e%252e/x",
    "https://example.com/%252E%252E%252F",
    "https://example.com/%25252e%25252e%25252f",
]


class TestTraversalIndependentOfCanonicalGate:
    @pytest.mark.parametrize("policy", ALL_POLICIES)
    @pytest.mark.parametrize("url", TRAVERSAL_VECTORS)
    def test_traversal_still_blocked(self, url: str, policy: str) -> None:
        with pytest.raises(InvalidURLError):
            parse_url(url, policy=policy)

    @pytest.mark.parametrize("policy", ALL_POLICIES)
    @pytest.mark.parametrize("url", DOUBLE_ENCODED_VECTORS)
    def test_double_encoding_still_blocked(self, url: str, policy: str) -> None:
        with pytest.raises(InvalidURLError):
            parse_url(url, policy=policy)

    def test_traversal_is_reported_as_traversal_not_as_canonical(self) -> None:
        with pytest.raises(InvalidURLError) as exc:
            parse_url("https://example.com/a/../b")
        assert exc.value.code is ErrorCode.PATH_TRAVERSAL


class TestNormalizationDoesNotCreateTraversal:
    """
    Decoding percent-escapes is only safe because the unreserved set contains
    no delimiters. If that allowlist ever widened to include ``%2F``, these
    inputs would start resolving into real ``../`` segments.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com/a%2F..%2Fb",
            "http://example.com/%2e%2e%2Fetc",
            "http://example.com/a%2f%2e%2e%2fb",
        ],
    )
    def test_encoded_delimiters_never_become_path_structure(self, url: str) -> None:
        try:
            parsed = parse_url(url, policy="internal")
        except InvalidURLError:
            return  # rejected outright is also an acceptable outcome
        assert "/../" not in parsed.path
        assert not parsed.path.endswith("/..")


class TestSsrfIndependentOfCanonicalGate:
    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/admin",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://[::1]/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://[::ffff:127.0.0.1]/",
            "http://[64:ff9b::10.0.0.1]/",
            # Case and trailing-dot variants: normalization must not create a
            # path around the SSRF check.
            "http://LOCALHOST/",
            "http://127.0.0.1./",
            "http://LocalHost./admin",
        ],
    )
    def test_ssrf_still_blocked_under_default_policy(self, url: str) -> None:
        with pytest.raises(InvalidURLError):
            parse_url(url)


class TestHostNormalizationClosesTheOldBypass:
    """
    The bug that motivated the change: with the gate switched off, 0.8 handed
    back an un-normalized host, so a caller's allowlist check silently missed.
    """

    @pytest.mark.parametrize("policy", ["strict", "balanced", "internal"])
    @pytest.mark.parametrize(
        "raw",
        ["http://EVIL.COM/", "http://evil.com./", "http://EvIl.CoM./", "http://Evil.Com/"],
    )
    def test_blocklist_cannot_be_evaded_by_spelling(self, raw: str, policy: str) -> None:
        assert parse_url(raw, policy=policy).host == "evil.com"
