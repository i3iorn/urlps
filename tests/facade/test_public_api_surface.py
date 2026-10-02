"""Snapshot of the public API surface.

``__all__`` and ``ErrorCode`` are the contract downstream code pins against, so
a change to either should be a deliberate edit to this file rather than
something that slips out in a release. This is a tripwire, not a design
statement -- if a change here is intended, update the expected set in the same
commit that makes it.
"""

from __future__ import annotations

import urlps
from urlps import ErrorCode

EXPECTED_ALL = {
    # Core
    "URL",
    "parse_url",
    "parse_url_local",
    "parse_url_unsafe",  # deprecated alias for parse_url_local
    "join",
    "build",
    "build_secure",
    "compose_url",
    # Connect-time SSRF guard
    "resolve_and_validate",
    "create_guarded_connection",
    # Policy / config
    "SecurityPolicy",
    "PolicyInput",
    "SecurityFinding",
    "AuditConfig",
    "AuditManager",
    "AuditCallback",
    "AuditEventCallback",
    "DNSRateLimiter",
    "DNSRateLimiterConfig",
    # Injectable I/O for the security checks
    "SecurityServices",
    "DNSResolutionCache",
    "DNSCacheConfig",
    "PhishingFeed",
    "PhishingDatabaseManager",
    "PhishingFeedConfig",
    # Caches
    "get_cache_info",
    "clear_all_caches",
    # Errors
    "ErrorCode",
    "URLpError",
    "InvalidURLError",
    "URLParseError",
    "URLBuildError",
    "UnsupportedSchemeError",
    "RelativeReferenceError",
    "QueryParsingError",
    "HostValidationError",
    "PortValidationError",
    "FragmentEncodingError",
    "UserInfoParsingError",
    "MissingHostError",
    "SecurityPolicyError",
    "PhishingDatabaseError",
    "DNSRateLimiterError",
    "DNSRebindingError",
    "DNSRateLimitError",
    "DNSResolutionError",
    "DNSConnectionError",
    # Metadata
    "__version__",
}

EXPECTED_ERROR_CODES = {
    "ssrf_risk",
    "dns_rate_limited",
    "dns_resolution_failed",
    "dns_connection_failed",
    "phishing_domain",
    "phishing_db_unavailable",
    "double_encoding",
    "path_traversal",
    "open_redirect",
    "parser_confusion",
    "credentials_in_url",
    "dangerous_port",
    "invalid_ipv6_zone_id",
    # Unicode host analysis (1.0)
    "confusable_host",
    "mixed_script_label",
    "idna_disallowed",
    "bidi_control_in_host",
    "zero_width_in_host",
    "invalid_punycode",
    "unsupported_scheme",
    "unsafe_scheme",
    # Deprecated, retained so downstream `except ... e.code is X` keeps
    # importing. Never emitted; removed in 2.0.
    "query_injection",
    "non_canonical_url",
    "mixed_scripts",
    "suspicious_punycode",
}

#: Codes the library no longer emits. Kept in ErrorCode for compatibility.
RETIRED_CODES = {
    "query_injection",
    "non_canonical_url",
    "mixed_scripts",
    "suspicious_punycode",
}


def test_all_matches_snapshot() -> None:
    actual = set(urlps.__all__)
    assert actual == EXPECTED_ALL, (
        f"public API changed.\n  added:   {sorted(actual - EXPECTED_ALL)}\n  removed: {sorted(EXPECTED_ALL - actual)}"
    )


def test_everything_in_all_is_importable() -> None:
    for name in urlps.__all__:
        assert hasattr(urlps, name), f"{name} is in __all__ but not present on the module"


def test_error_codes_match_snapshot() -> None:
    actual = {code.value for code in ErrorCode}
    assert actual == EXPECTED_ERROR_CODES, (
        f"ErrorCode changed.\n  added:   {sorted(actual - EXPECTED_ERROR_CODES)}\n"
        f"  removed: {sorted(EXPECTED_ERROR_CODES - actual)}"
    )


def test_every_exception_class_is_exported() -> None:
    """Every exception subclass must be reachable from the package root."""
    import urlps.exceptions as exceptions

    classes = {
        name
        for name in dir(exceptions)
        if isinstance(getattr(exceptions, name), type) and issubclass(getattr(exceptions, name), Exception)
    }
    assert classes <= set(urlps.__all__), f"not exported: {sorted(classes - set(urlps.__all__))}"


def test_retired_codes_are_never_emitted() -> None:
    """They stay in the enum for compatibility, but nothing produces them."""
    from urlps._security import _REMEDIATION_BY_CODE

    hostile = [
        "https://example.com/?q=WAITFOR",  # was query_injection
        "HTTP://EXAMPLE.COM./",  # was non_canonical_url
        "http://xn--pypal-4ve.com/",  # was mixed_scripts / suspicious_punycode
    ]
    for raw in hostile:
        try:
            urlps.parse_url(raw)
        except urlps.URLpError as exc:
            assert exc.code is None or exc.code.value not in RETIRED_CODES, (
                f"{raw} still reports retired code {exc.code}"
            )

    # And nothing advertises remediation for a code that cannot occur.
    assert not {code.value for code in _REMEDIATION_BY_CODE} & RETIRED_CODES


def test_typed_marker_is_present() -> None:
    from pathlib import Path

    assert (Path(urlps.__file__).parent / "py.typed").is_file()


#: SecurityPolicy's positional order as released in 1.1.4. It is a dataclass,
#: so SecurityPolicy("x", True, ...) binds by position: a field inserted among
#: these silently moves every later argument onto a different setting.
POLICY_FIELDS_1_1 = [
    "name",
    "enforce_ssrf",
    "allow_private_hosts",
    "enforce_path_traversal",
    "enforce_open_redirect",
    "enforce_mixed_scripts",
    "enforce_parser_confusion",
    "enforce_double_encoding",
    "block_dangerous_ports",
    "reject_credentials",
    "enforce_suspicious_punycode",
    "enforce_confusable_host",
    "enforce_host_unicode_safety",
    "check_dns",
    "check_phishing",
    "enforce_dns_rate_limit",
    "dns_fail_open_on_connect_error",
    "dns_retries",
    "dns_backoff_base_seconds",
    "dns_backoff_jitter_seconds",
    "dns_rate_limiter",
]


def test_policy_keeps_its_released_positional_order() -> None:
    import dataclasses

    names = [f.name for f in dataclasses.fields(urlps.SecurityPolicy)]
    assert names[: len(POLICY_FIELDS_1_1)] == POLICY_FIELDS_1_1, "add new SecurityPolicy fields at the end"


def test_removed_constant_is_still_importable_with_a_warning() -> None:
    import pytest

    import urlps.constants as constants

    with pytest.warns(DeprecationWarning, match="STANDARD_PORTS"):
        from urlps.constants import STANDARD_PORTS
    assert frozenset({80, 443}) <= STANDARD_PORTS
    with pytest.raises(AttributeError):
        _ = constants.NO_SUCH_CONSTANT
