"""create_guarded_connection()'s exception contract.

``_egress`` is a drop-in for ``socket.create_connection`` / urllib3's
``create_connection``, and the docstring promises "the usual OSError
subclasses" for network failures. A resolution failure would, in the
unguarded stack, surface as ``socket.gaierror`` -- an OSError that retry
logic in urllib3/requests (and everyone's `except OSError` handlers)
catches. A plain-Exception escape instead bypasses all of that and lands
as a generic error, so ``DNSResolutionError`` is both:
``InvalidURLError`` (the parse-path contract) *and* ``OSError``.
"""

from __future__ import annotations

import pytest

from urlps import DNSResolutionError, InvalidURLError
from urlps._egress import _vetted_addrinfo
from urlps._security.dns_guard import default_resolver
from urlps._security.policy import SecurityPolicy


class TestDNSResolutionErrorHierarchies:
    def test_is_oserror(self):
        assert issubclass(DNSResolutionError, OSError)

    def test_is_still_invalid_url_error(self):
        assert issubclass(DNSResolutionError, InvalidURLError)

    def test_caught_by_except_oserror(self):
        with pytest.raises(OSError):
            raise DNSResolutionError("boom")

    def test_caught_by_except_invalid_url_error(self):
        with pytest.raises(InvalidURLError):
            raise DNSResolutionError("boom")


class TestVettedAddrinfoErrorContract:
    def test_idna_unencodable_host_becomes_dns_resolution_error(self):
        # getaddrinfo enforces IDNA in-process; a 64-character label raises
        # UnicodeError, not gaierror, and that used to escape _vetted_addrinfo
        # as a non-OSError, non-InvalidURLError exception. No DNS traffic is
        # needed for this case: UnicodeError is raised before any packet is
        # sent (and if some platform ever resolves it instead, the real
        # resolver fails with gaierror -> still DNSResolutionError).
        policy = SecurityPolicy.strict()
        with pytest.raises(DNSResolutionError):
            _vetted_addrinfo("a" * 64 + ".com", 443, policy, dns_timeout=2.0, resolver=default_resolver)
