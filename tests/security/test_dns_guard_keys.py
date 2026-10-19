"""DNS cache/rate-limiter key normalization and error-contract coverage.

Two issues that only surface when the DNS layer is called directly (i.e.
with a hostname that did not go through parse_url) or attack DNS state
with spelling variants:

- Trailing FQDN dots: "example.com." is the same name getaddrinfo
  resolves, but as a dict key it was distinct from "example.com" -- so an
  attacker cycling trailing-dot spellings got a fresh per-host rate-limit
  budget each time, and a failed resolution of one spelling was not
  negative-cached for the plain spelling.
- A label the IDNA codec cannot encode made ``socket.getaddrinfo`` raise
  UnicodeError, which escaped ``check_host_resolution`` as neither a DNS
  error code nor an OSError.
"""

from __future__ import annotations

from urlps._security.dns_guard import _validate_host, check_host_resolution
from urlps.exceptions import ErrorCode


def test_validate_host_strips_trailing_fqdn_dot():
    assert _validate_host("example.com.") == "example.com"


def test_validate_host_strips_multiple_trailing_dots():
    assert _validate_host("example.com..") == "example.com"


def test_validate_host_only_dots_is_invalid():
    assert _validate_host("...") is None


def test_validate_host_untouched_without_dots():
    assert _validate_host("example.com") == "example.com"
    assert _validate_host("  example.com  ") == "example.com"
    assert _validate_host("203.0.113.9.") == "203.0.113.9"


class TestCheckHostResolutionErrorContract:
    def test_unicode_error_from_idna_becomes_dns_resolution_failed(self):
        # A 64-character label: getaddrinfo enforces IDNA in-process and
        # raises UnicodeError ("label too long"), which used to escape this
        # function entirely. The resulting error is negative-cacheable
        # (deterministic), and the module only negative-caches
        # DNS_RESOLUTION_FAILED -- so that is the right code, not
        # DNS_CONNECTION_FAILED.
        result = check_host_resolution("a" * 64 + ".com")
        assert result.error == ErrorCode.DNS_RESOLUTION_FAILED
