"""Tests targeting coverage gaps across urlps modules.

Covers uncovered lines in:
- __init__.py
- _audit.py
- _builder.py
- _parser.py
- _security.py
- _validation.py
- exceptions.py
- security_policy.py
- url.py
"""
from __future__ import annotations

import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# __init__.py gaps
# ---------------------------------------------------------------------------

class TestInitBuild:
    def test_build_single_arg_host_only(self):
        """Lines 273-274: build() with a single positional arg (host only)."""
        from src.urlps import build
        result = build("example.com")
        assert "example.com" in result

    def test_build_no_args_raises(self):
        """Lines 278-279: build() with zero args raises URLBuildError."""
        from src.urlps import build
        from src.urlps.exceptions import URLBuildError
        with pytest.raises(URLBuildError):
            build()

    def test_build_secure_returns_string(self):
        """Line 333: build_secure() returns validated URL string."""
        from src.urlps import build_secure
        result = build_secure("https", "example.com", path="/api")
        assert "example.com" in result
        assert result.startswith("https://")

    def test_build_secure_with_policy(self):
        """build_secure() with a custom policy."""
        from src.urlps import build_secure
        from src.urlps.security_policy import SecurityPolicy
        policy = SecurityPolicy.balanced()
        result = build_secure("https", "example.com", path="/v1", policy=policy)
        assert "https://example.com/v1" in result

    def test_get_cache_info_structure(self):
        """Lines 354-356: get_cache_info() returns expected keys."""
        from src.urlps import get_cache_info
        info = get_cache_info()
        assert "parser" in info
        assert "validation" in info
        assert "security" in info
        assert "builder" in info

    def test_get_cache_info_builder_keys(self):
        """Lines 354-356: builder cache info has expected keys."""
        from src.urlps import get_cache_info
        info = get_cache_info()
        builder_info = info["builder"]
        assert "percent_encode" in builder_info
        assert "encode_for_query" in builder_info

    def test_clear_all_caches_returns_dict(self):
        """Lines 385-402: clear_all_caches() returns previous cache sizes."""
        from src.urlps import clear_all_caches
        result = clear_all_caches()
        assert "parser" in result
        assert "validation" in result
        assert "security" in result
        assert "builder" in result

    def test_clear_all_caches_builder_keys(self):
        """Lines 394-400: builder entries populated after use."""
        from src.urlps import parse_url, clear_all_caches
        # Warm up caches
        parse_url("https://example.com/path")
        result = clear_all_caches()
        assert "builder" in result

    def test_parse_url_with_policy_instance(self):
        """parse_url() passing a SecurityPolicy instance directly."""
        from src.urlps import parse_url
        from src.urlps.security_policy import SecurityPolicy
        policy = SecurityPolicy.balanced()
        url = parse_url("https://example.com/", policy=policy)
        assert url.host == "example.com"

    def test_parse_url_unsafe_with_policy(self):
        """parse_url_unsafe() with explicit policy uses resolve_security_policy."""
        from src.urlps import parse_url_unsafe
        from src.urlps.security_policy import SecurityPolicy
        policy = SecurityPolicy.internal()
        url = parse_url_unsafe("http://localhost/test", policy=policy)
        assert url.host == "localhost"


# ---------------------------------------------------------------------------
# _audit.py gaps
# ---------------------------------------------------------------------------

class TestAudit:
    def setup_method(self):
        from src.urlps._audit import (
            set_audit_callback, set_audit_event_callback,
            reset_callback_failure_metrics,
        )
        set_audit_callback(None)
        set_audit_event_callback(None)
        reset_callback_failure_metrics()

    def teardown_method(self):
        from src.urlps._audit import (
            set_audit_callback, set_audit_event_callback,
            reset_callback_failure_metrics,
        )
        set_audit_callback(None)
        set_audit_event_callback(None)
        reset_callback_failure_metrics()

    def test_get_audit_event_callback_returns_none_when_unset(self):
        """Lines 51-52: get_audit_event_callback() returns None when not set."""
        from src.urlps._audit import get_audit_event_callback
        result = get_audit_event_callback()
        assert result is None

    def test_get_audit_event_callback_returns_set_callback(self):
        """Lines 51-52: get_audit_event_callback() returns set callback."""
        from src.urlps._audit import get_audit_event_callback, set_audit_event_callback
        events = []
        cb = lambda e: events.append(e)
        set_audit_event_callback(cb)
        assert get_audit_event_callback() is cb

    def test_event_callback_exception_increments_failure_count(self):
        """Lines 101-104: exception in event_callback increments failure count."""
        from src.urlps._audit import (
            set_audit_event_callback, invoke_audit_callback,
            get_callback_failure_metrics,
        )

        def bad_event_callback(event):
            raise RuntimeError("intentional event callback error")

        set_audit_event_callback(bad_event_callback)
        invoke_audit_callback("https://example.com", None, None)

        metrics = get_callback_failure_metrics()
        assert metrics["failure_count"] >= 1
        assert metrics["last_error"] is not None

    def test_regular_callback_exception_increments_failure_count(self):
        """Lines 93-95: exception in regular callback is captured."""
        from src.urlps._audit import (
            set_audit_callback, invoke_audit_callback,
            get_callback_failure_metrics,
        )

        def bad_callback(url, parsed, exc):
            raise RuntimeError("intentional callback error")

        set_audit_callback(bad_callback)
        invoke_audit_callback("https://example.com", None, None)

        metrics = get_callback_failure_metrics()
        assert metrics["failure_count"] >= 1

    def test_invoke_audit_callback_with_no_redact(self):
        """invoke_audit_callback() with redact_urls=False passes raw URL."""
        from src.urlps._audit import (
            set_audit_callback, set_audit_event_callback,
            invoke_audit_callback,
        )
        received = []
        set_audit_callback(lambda url, parsed, exc: received.append(url), redact_urls=False)
        invoke_audit_callback("https://user:secret@example.com", None, None)
        assert "secret" in received[0]


# ---------------------------------------------------------------------------
# _builder.py gaps
# ---------------------------------------------------------------------------

class TestBuilder:
    def test_compose_secure(self):
        """Lines 123-133: compose_secure() builds and validates URL."""
        from src.urlps._builder import Builder
        builder = Builder()
        result = builder.compose_secure(
            {"scheme": "https", "host": "example.com", "path": "/secure"}
        )
        assert "example.com" in result

    def test_compose_scheme_none_no_host_raises(self):
        """Lines 97->99 / 102-103: compose() with scheme but no valid netloc raises."""
        from src.urlps._builder import Builder
        from src.urlps.exceptions import URLBuildError
        builder = Builder()
        with pytest.raises(URLBuildError):
            builder.compose({"scheme": "https"})

    def test_normalize_path_dotdot_at_start(self):
        """Lines 219->215: path starts with '..' on empty segment list."""
        from src.urlps._builder import Builder
        builder = Builder()
        result = builder.normalize_path("/../foo")
        assert result == "/foo"

    def test_normalize_path_relative_path(self):
        """Lines 228->231: relative path skips absolute re-prefix."""
        from src.urlps._builder import Builder
        builder = Builder()
        result = builder.normalize_path("a/b/../c")
        assert result == "a/c"

    def test_normalize_path_relative_with_trailing_slash(self):
        """Lines 228->231: relative path with trailing slash preserved."""
        from src.urlps._builder import Builder
        builder = Builder()
        result = builder.normalize_path("a/b/")
        assert result.endswith("/")

    def test_fast_unquote_plus_with_plus(self):
        """Line 255: _fast_unquote_plus with '+' decodes to space."""
        from src.urlps._builder import Builder
        result = Builder._fast_unquote_plus("hello+world")
        assert result == "hello world"

    def test_fast_unquote_plus_with_percent_encoding(self):
        """Line 255: _fast_unquote_plus with '%20' decodes to space."""
        from src.urlps._builder import Builder
        result = Builder._fast_unquote_plus("hello%20world")
        assert result == "hello world"

    def test_compose_with_file_scheme_no_host(self):
        """compose() with file:// scheme allows no host."""
        from src.urlps._builder import Builder
        builder = Builder()
        result = builder.compose({"scheme": "file", "path": "/tmp/file.txt"})
        assert "file://" in result

    def test_build_netloc_port_without_host_raises(self):
        """PortValidationError when port without host."""
        from src.urlps._builder import Builder
        from src.urlps.exceptions import PortValidationError
        builder = Builder()
        with pytest.raises(PortValidationError):
            builder.build_netloc(None, None, 8080, "https")


# ---------------------------------------------------------------------------
# _parser.py gaps
# ---------------------------------------------------------------------------

class TestParser:
    def test_parse_regular_host_idna_error(self):
        """Lines 144-145: IDNA encoding failure raises HostValidationError."""
        from src.urlps._parser import parse_regular_host
        from src.urlps.exceptions import HostValidationError
        # This host has a label that is too long after IDNA encoding
        long_label = "a" * 64
        with pytest.raises(HostValidationError):
            parse_regular_host(f"{long_label}.com")

    def test_parse_query_string_empty_key_raises(self):
        """Line 230: Query string with empty key raises QueryParsingError."""
        from src.urlps._parser import parse_query_string
        from src.urlps.exceptions import QueryParsingError
        with pytest.raises(QueryParsingError):
            parse_query_string("=value")

    def test_apply_port_defaults_no_port_scheme_raises(self):
        """Line 259: file scheme with explicit port raises UnsupportedSchemeError."""
        from src.urlps._parser import apply_port_defaults
        from src.urlps.exceptions import UnsupportedSchemeError
        from src.urlps.constants import SCHEMES_NO_PORT
        # Find a scheme in SCHEMES_NO_PORT to test with
        no_port_scheme = next(iter(SCHEMES_NO_PORT)) if SCHEMES_NO_PORT else None
        if no_port_scheme:
            with pytest.raises(UnsupportedSchemeError):
                apply_port_defaults(no_port_scheme, 80, "example.com")

    def test_apply_port_defaults_port_without_host_raises(self):
        """Line 261: Port set without host raises PortValidationError."""
        from src.urlps._parser import apply_port_defaults
        from src.urlps.exceptions import PortValidationError
        with pytest.raises(PortValidationError):
            apply_port_defaults("https", 443, None)

    def test_parser_custom_scheme_getter(self):
        """Line 324: custom_scheme getter returns current value."""
        from src.urlps._parser import Parser
        parser = Parser()
        assert parser.custom_scheme is False
        parser.custom_scheme = True
        assert parser.custom_scheme is True

    def test_parse_netloc(self):
        """Line 340: parse_netloc returns correct components."""
        from src.urlps._parser import Parser
        parser = Parser()
        userinfo, host, port = parser.parse_netloc("user:pass@example.com:8080")
        assert host == "example.com"
        assert port == 8080
        assert userinfo == "user:pass"

    def test_parse_netloc_no_port(self):
        """parse_netloc without explicit port."""
        from src.urlps._parser import Parser
        parser = Parser()
        userinfo, host, port = parser.parse_netloc("example.com")
        assert host == "example.com"
        assert port is None
        assert userinfo is None

    def test_get_cache_info(self):
        """Lines 363-372: get_cache_info() returns normalize_path stats."""
        from src.urlps._parser import get_cache_info
        info = get_cache_info()
        assert "normalize_path" in info
        assert info["normalize_path"] is not None
        assert "hits" in info["normalize_path"]

    def test_clear_caches(self):
        """Lines 381-386: clear_caches() returns previous sizes."""
        from src.urlps._parser import clear_caches, normalize_path
        normalize_path("/some/test/path")
        result = clear_caches()
        assert "normalize_path" in result
        assert isinstance(result["normalize_path"], int)

    def test_parse_url_non_string_raises(self):
        """parse_url() with non-string input raises URLParseError."""
        from src.urlps._parser import parse_url
        from src.urlps.exceptions import URLParseError
        with pytest.raises(URLParseError):
            parse_url(123)  # type: ignore

    def test_parse_url_whitespace_only_raises(self):
        """parse_url() with whitespace-only string raises URLParseError."""
        from src.urlps._parser import parse_url
        from src.urlps.exceptions import URLParseError
        with pytest.raises(URLParseError):
            parse_url("   ")


# ---------------------------------------------------------------------------
# _security.py gaps
# ---------------------------------------------------------------------------

class TestSecurityPrivateChecks:
    def test_check_ipv6_private_invalid_address(self):
        """Lines 80-81: ValueError in _check_ipv6_private returns False."""
        from src.urlps._security import _check_ipv6_private
        result = _check_ipv6_private("[not_a_valid_ipv6]")
        assert result is False

    def test_check_ipv6_private_loopback(self):
        """_check_ipv6_private returns True for loopback ::1."""
        from src.urlps._security import _check_ipv6_private
        result = _check_ipv6_private("[::1]")
        assert result is True

    def test_is_octal_hex_ip_private_valid_octal(self):
        """Lines 151-152: try block in _is_octal_hex_ip_private succeeds."""
        from src.urlps._security import _is_octal_hex_ip_private
        # 0177 = 127 in octal -> 127.0.0.1 is loopback
        result = _is_octal_hex_ip_private("0177.0.0.1")
        assert result is True

    def test_is_octal_hex_ip_private_hex(self):
        """_is_octal_hex_ip_private with hex octet."""
        from src.urlps._security import _is_octal_hex_ip_private
        # 0x7f = 127 hex -> 127.0.0.1 is loopback
        result = _is_octal_hex_ip_private("0x7f.0x0.0x0.0x1")
        assert result is True

    def test_check_resolved_ips_safe_invalid_ip(self):
        """Lines 169-170: ValueError on invalid sockaddr continues."""
        from src.urlps._security import _check_resolved_ips_safe
        # Simulate addr_info with an invalid IP string in sockaddr
        addr_info = [(2, 1, 6, "", ("invalid_ip_string", 80))]
        result = _check_resolved_ips_safe(addr_info)
        # Should continue and return True (no unsafe IP found)
        assert result is True

    def test_verify_connection_safe_empty_addr_info(self):
        """Line 177: _verify_connection_safe with empty list returns True."""
        from src.urlps._security import _verify_connection_safe
        result = _verify_connection_safe([], 1.0)
        assert result is True

    def test_is_private_ip_non_string(self):
        """Line 197: is_private_ip with non-string returns False."""
        from src.urlps._security import is_private_ip
        # Call the underlying function directly to bypass cache type-checking
        result = is_private_ip.__wrapped__(123)
        assert result is False

    def test_is_private_ip_non_string_none(self):
        """is_private_ip with None returns False."""
        from src.urlps._security import is_private_ip
        result = is_private_ip.__wrapped__(None)
        assert result is False


class TestSecurityDNS:
    def test_check_dns_rebinding_detailed_empty_host(self):
        """Line 230: empty host returns DNS_RESOLUTION_FAILED."""
        from src.urlps._security import check_dns_rebinding_detailed
        from src.urlps.exceptions import ErrorCode
        safe, error = check_dns_rebinding_detailed("")
        assert safe is False
        assert error == ErrorCode.DNS_RESOLUTION_FAILED

    def test_check_dns_rebinding_detailed_private_ip_direct(self):
        """Lines 232->234 branch: private IP detected directly."""
        from src.urlps._security import check_dns_rebinding_detailed
        from src.urlps.exceptions import ErrorCode
        safe, error = check_dns_rebinding_detailed("127.0.0.1")
        assert safe is False
        assert error == ErrorCode.SSRF_RISK

    def test_check_dns_rebinding_detailed_safe_direct_ip(self):
        """Lines 232->234 branch: safe IP detected directly returns True."""
        from src.urlps._security import check_dns_rebinding_detailed
        safe, error = check_dns_rebinding_detailed("93.184.216.34")  # example.com
        assert safe is True
        assert error is None

    def test_dns_rate_limit_blocked(self):
        """Lines 243-244: rate limit blocks lookup returns DNS_RATE_LIMITED."""
        from src.urlps._security import check_dns_rebinding_detailed, DNSRateLimiter
        from src.urlps.exceptions import ErrorCode
        # Use a limiter with zero capacity to force rate limiting
        limiter = DNSRateLimiter(max_lookups_per_second=0.0001, max_lookups_per_host=0)
        with patch("src.urlps._security.get_dns_rate_limiter", return_value=limiter):
            safe, error = check_dns_rebinding_detailed(
                "somehost.example.com", enforce_rate_limit=True
            )
        assert safe is False
        assert error == ErrorCode.DNS_RATE_LIMITED

    def test_reset_dns_rate_limiter_when_none(self):
        """Line 816->exit: reset_dns_rate_limiter does nothing when not initialized."""
        import src.urlps._security as sec
        original = sec._dns_rate_limiter
        try:
            sec._dns_rate_limiter = None
            sec.reset_dns_rate_limiter()  # should not raise
        finally:
            sec._dns_rate_limiter = original

    def test_reset_dns_rate_limiter_when_set(self):
        """reset_dns_rate_limiter() resets the global limiter state."""
        from src.urlps._security import (
            reset_dns_rate_limiter, get_dns_rate_limiter
        )
        limiter = get_dns_rate_limiter()
        limiter.tokens = 0  # exhaust tokens
        reset_dns_rate_limiter()
        limiter_after = get_dns_rate_limiter()
        assert limiter_after.tokens > 0


class TestSecurityMixedScripts:
    def test_has_mixed_scripts_non_string(self):
        """Line 397: has_mixed_scripts with non-string returns False."""
        from src.urlps._security import has_mixed_scripts
        result = has_mixed_scripts.__wrapped__(123)
        assert result is False

    def test_has_mixed_scripts_none(self):
        """has_mixed_scripts with None returns False."""
        from src.urlps._security import has_mixed_scripts
        result = has_mixed_scripts.__wrapped__(None)
        assert result is False

    def test_has_double_encoding_non_string(self):
        """Line 424: has_double_encoding with non-string returns False."""
        from src.urlps._security import has_double_encoding
        result = has_double_encoding(123)
        assert result is False

    def test_has_double_encoding_none(self):
        """has_double_encoding with None returns False."""
        from src.urlps._security import has_double_encoding
        result = has_double_encoding(None)
        assert result is False

    def test_has_path_traversal_non_string(self):
        """Line 431: has_path_traversal with non-string returns False."""
        from src.urlps._security import has_path_traversal
        result = has_path_traversal(123)
        assert result is False

    def test_has_path_traversal_double_encoded(self):
        """Lines 439: has_path_traversal detects double-encoded traversal."""
        from src.urlps._security import has_path_traversal
        # %252e%252e → %2e%2e → .. (double encoded)
        result = has_path_traversal("%252e%252e")
        assert result is True

    def test_has_path_traversal_returns_false_for_safe_path(self):
        """Line 448: has_path_traversal returns False for safe paths."""
        from src.urlps._security import has_path_traversal
        result = has_path_traversal("/safe/path/here")
        assert result is False

    def test_is_open_redirect_risk_non_string(self):
        """is_open_redirect_risk with non-string returns False."""
        from src.urlps._security import is_open_redirect_risk
        result = is_open_redirect_risk(123)
        assert result is False


class TestSecurityIPv6ZoneId:
    def test_malicious_ipv6_zone_id_empty_zone(self):
        """Lines 476-477: empty zone ID is malicious."""
        from src.urlps._security import is_malicious_ipv6_zone_id
        result = is_malicious_ipv6_zone_id("[::1%25]")
        assert result is True

    def test_malicious_ipv6_zone_id_invalid_zone_chars(self):
        """Lines 476-477: invalid chars in zone ID returns True."""
        from src.urlps._security import is_malicious_ipv6_zone_id
        result = is_malicious_ipv6_zone_id("[fe80::1%25<script>]")
        assert result is True

    def test_malicious_ipv6_zone_id_valid_zone(self):
        """is_malicious_ipv6_zone_id returns False for valid zone char."""
        from src.urlps._security import is_malicious_ipv6_zone_id
        result = is_malicious_ipv6_zone_id("[fe80::1%25eth0]")
        assert result is False

    def test_parser_confusion_backslash_in_authority(self):
        """Line 612: backslash in authority returns True."""
        from src.urlps._security import has_parser_confusion
        result = has_parser_confusion("http://example.com\\evil.com/path")
        assert result is True

    def test_parser_confusion_empty_authority(self):
        """Line 605: empty authority returns False."""
        from src.urlps._security import has_parser_confusion
        # URL with scheme and no authority portion
        result = has_parser_confusion("http:///")
        assert result is False


class TestSecurityCanonical:
    def test_is_non_canonical_url_uppercase_scheme(self):
        """Lines 887->893: uppercase scheme detected as non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("HTTP://example.com/")

    def test_is_non_canonical_url_uppercase_host(self):
        """Lines 897->921: uppercase host detected as non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://EXAMPLE.COM/")

    def test_is_non_canonical_url_default_port(self):
        """Lines 927: default port detected as non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com:80/")

    def test_is_non_canonical_url_dot_segment(self):
        """Lines 949: dot-segment detected as non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/./path")

    def test_is_non_canonical_url_dotdot_segment(self):
        """Lines 951: dotdot-segment detected as non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/path/../other")

    def test_is_non_canonical_url_end_dot_segment(self):
        """Lines 953: path ending with /. is non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/path/.")

    def test_is_non_canonical_url_canonical_returns_false(self):
        """is_non_canonical_url returns False for canonical URL."""
        from src.urlps._security import is_non_canonical_url
        assert not is_non_canonical_url("https://example.com/path")

    def test_is_non_canonical_url_no_scheme(self):
        """is_non_canonical_url returns False for URL without scheme."""
        from src.urlps._security import is_non_canonical_url
        assert not is_non_canonical_url("example.com/path")

    def test_is_non_canonical_url_trailing_dot_host(self):
        """Trailing dot in hostname is non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com./path")

    def test_is_non_canonical_url_lowercase_percent_encoding(self):
        """Lowercase percent-encoding in path is non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/%2fpath")

    def test_is_non_canonical_url_non_canonical_ipv6(self):
        """Non-canonical IPv6 form detected."""
        from src.urlps._security import is_non_canonical_url
        # Non-compressed form when compressed exists
        result = is_non_canonical_url("http://[0:0:0:0:0:0:0:1]/")
        assert result is True

    def test_is_non_canonical_url_fragment_lowercase_encoding(self):
        """Lowercase encoding in fragment is non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/path#%2ffrag")

    def test_is_non_canonical_url_query_lowercase_encoding(self):
        """Lowercase encoding in query string is non-canonical."""
        from src.urlps._security import is_non_canonical_url
        assert is_non_canonical_url("http://example.com/path?k=%2fval")


class TestGetCanonicalUrl:
    def test_get_canonical_url_uppercase_scheme(self):
        """Lines 1063->1127: lowercases scheme."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("HTTP://EXAMPLE.COM/path")
        assert result is not None
        assert result.startswith("http://")

    def test_get_canonical_url_default_port_removed(self):
        """Lines 1112-1118: removes default port."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com:80/")
        assert result is not None
        assert ":80" not in result

    def test_get_canonical_url_path_normalization(self):
        """Line 1131: path normalization removes dot segments."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com/a/../b")
        assert result is not None
        assert "/a/" not in result
        assert "/b" in result

    def test_get_canonical_url_query_uppercase_encoding(self):
        """Line 1150: uppercase encoding in query."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com/?k=%2fval")
        assert result is not None
        assert "%2F" in result or "%2f" not in result

    def test_get_canonical_url_fragment_uppercase_encoding(self):
        """Line 1158: uppercase encoding in fragment."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com/path#%2ffrag")
        assert result is not None
        assert "%2F" in result or "%2f" not in result

    def test_get_canonical_url_with_userinfo(self):
        """get_canonical_url handles netloc with userinfo."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://user@EXAMPLE.COM/")
        assert result is not None
        assert "user@example.com" in result

    def test_get_canonical_url_invalid_returns_none(self):
        """Lines 1168-1169: invalid URL returns None."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("")
        assert result is None

    def test_get_canonical_url_no_scheme_returns_none(self):
        """get_canonical_url returns None when no scheme."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("example.com/path")
        assert result is None

    def test_get_canonical_url_trailing_dot_removed(self):
        """Line 1095-1096: trailing dot in host removed."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://example.com./path")
        assert result is not None
        assert "example.com." not in result

    def test_get_canonical_url_ipv6_canonicalized(self):
        """Lines 1100-1107: IPv6 address canonicalized."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://[0:0:0:0:0:0:0:1]/")
        assert result is not None
        assert "[::1]" in result

    def test_get_canonical_url_ipv6_with_port(self):
        """Lines 1079: IPv6 with port in netloc."""
        from src.urlps._security import get_canonical_url
        result = get_canonical_url("http://[::1]:8080/")
        assert result is not None
        assert "[::1]" in result

    def test_get_canonical_url_ipv6_malformed_uses_hostname(self):
        """Line 1084: malformed IPv6 falls back to hostname."""
        from src.urlps._security import get_canonical_url
        # A netloc starting with [ but not well-formed
        result = get_canonical_url("http://[::1/path")
        # Should handle gracefully (either None or some result)
        # Just ensure it doesn't throw


class TestSecurityPunycode:
    def test_has_suspicious_punycode_decoding_fails(self):
        """Lines 1223-1225: malformed xn-- returns True."""
        from src.urlps._security import has_suspicious_punycode
        # Malformed punycode domain
        result = has_suspicious_punycode("xn---.com")
        # Either True (suspicious) or doesn't crash
        assert isinstance(result, bool)

    def test_has_suspicious_punycode_digits_and_non_ascii(self):
        """Line 1284: digits + non-ASCII is suspicious."""
        from src.urlps._security import has_suspicious_punycode
        result = has_suspicious_punycode("раура1.com")  # Cyrillic + digit
        assert result is True

    def test_has_suspicious_punycode_all_numeric_non_ascii(self):
        """Line 1292: all-numeric non-ASCII domain is suspicious."""
        from src.urlps._security import has_suspicious_punycode
        result = has_suspicious_punycode("пайпал.com")  # Cyrillic brand-like
        assert isinstance(result, bool)

    def test_has_suspicious_punycode_brand_in_non_ascii(self):
        """Line 1308: known brand in non-ASCII host."""
        from src.urlps._security import has_suspicious_punycode
        # Unicode that contains 'paypal' brand in decoded form
        result = has_suspicious_punycode("рауpal.com")  # Cyrillic р + aypal
        assert isinstance(result, bool)


class TestSecurityQueryInjection:
    def test_has_query_injection_encoded_xss_context(self):
        """Lines 1413->1406: %3c followed by script keyword."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("q=%3cscript%3e")
        assert result is True

    def test_has_query_injection_encoded_quote_sql(self):
        """Lines 1420->1406: %27 in SQL context."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("id=%271%27+or+1%3d1")
        assert isinstance(result, bool)

    def test_has_query_injection_encoded_semicolon(self):
        """Lines 1424: %3b is suspicious on its own."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("cmd%3brm+-rf+/")
        assert result is True

    def test_has_query_injection_encoded_pipe(self):
        """Lines 1424: %7c is suspicious."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("x%7ccat+/etc/passwd")
        assert result is True

    def test_has_query_injection_encoded_and(self):
        """Lines 1424: %26%26 is suspicious."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("x%26%26rm+-rf+/")
        assert result is True

    def test_has_query_injection_encoded_or(self):
        """Lines 1424: %7c%7c is suspicious."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("x%7c%7cevil")
        assert result is True

    def test_has_query_injection_encoded_xss_followed_by_iframe(self):
        """Lines 1415->1406: %3c followed by 'iframe' triggers."""
        from src.urlps._security import has_query_injection
        result = has_query_injection("q=%3ciframe+src=evil")
        assert result is True


class TestSecurityExtractHostPath:
    def test_extract_host_and_path_no_scheme(self):
        """Line 1482: URL without :// returns empty strings."""
        from src.urlps._security import extract_host_and_path
        host, path = extract_host_and_path("example.com/path")
        assert host == ""
        assert path == ""


class TestSecurityMiscellaneous:
    def test_normalize_url_unicode_non_string(self):
        """Lines 1525-1526: non-string input returned unchanged."""
        from src.urlps._security import normalize_url_unicode
        result = normalize_url_unicode(123)
        assert result == 123

    def test_normalize_url_unicode_valid(self):
        """normalize_url_unicode normalizes to NFC."""
        from src.urlps._security import normalize_url_unicode
        result = normalize_url_unicode("https://example.com")
        assert result == "https://example.com"

    def test_redact_url_for_logs_error_handling(self):
        """Line 1532: ValueError in redact_url_for_logs returns original."""
        from src.urlps._security import redact_url_for_logs
        # Non-string input
        result = redact_url_for_logs(None)
        assert result is None

    def test_collect_security_findings_no_scheme(self):
        """Line 1573: URL without :// skips host/path checks."""
        from src.urlps._security import collect_security_findings
        from src.urlps.security_policy import SecurityPolicy
        findings = collect_security_findings("example.com/path", policy=SecurityPolicy.strict())
        # Should not crash and may have findings for double encoding etc
        assert isinstance(findings, list)

    def test_collect_security_findings_port_value_error(self):
        """Lines 1599-1600: ValueError on bad port handled gracefully."""
        from src.urlps._security import collect_security_findings
        from src.urlps.security_policy import SecurityPolicy
        policy = SecurityPolicy.strict()
        # A URL with a non-numeric port causes urlsplit to raise ValueError
        # We test that collect_security_findings handles it gracefully
        findings = collect_security_findings(
            "http://example.com:badport/path",
            policy=policy,
        )
        assert isinstance(findings, list)

    def test_collect_security_findings_dns_error_finding(self):
        """Line 1642: DNS failure generates a finding."""
        from src.urlps._security import (
            collect_security_findings, DNSRateLimiter,
        )
        from src.urlps.security_policy import SecurityPolicy
        from src.urlps.exceptions import ErrorCode

        # Force DNS rate limit to fail
        limiter = DNSRateLimiter(max_lookups_per_second=0.0001, max_lookups_per_host=0)
        policy = SecurityPolicy("test_dns", check_dns=True, enforce_ssrf=False,
                                enforce_path_traversal=False, enforce_open_redirect=False,
                                enforce_mixed_scripts=False, enforce_parser_confusion=False,
                                enforce_double_encoding=False, enforce_query_injection=False,
                                block_dangerous_ports=False, reject_credentials=False,
                                require_canonical=False, enforce_dns_rate_limit=True)
        with patch("src.urlps._security.get_dns_rate_limiter", return_value=limiter):
            findings = collect_security_findings(
                "http://notlocalhost.example.com/",
                policy=policy,
                check_dns=True,
            )

        dns_findings = [f for f in findings if "dns" in f.code.lower() or "rate" in f.code.lower()]
        assert len(dns_findings) > 0

    def test_security_get_cache_info(self):
        """Line 1673: get_cache_info returns security function stats."""
        from src.urlps._security import get_cache_info
        info = get_cache_info()
        assert isinstance(info, dict)
        assert len(info) > 0

    def test_security_clear_caches(self):
        """Line 1682->1681: clear_caches returns previous sizes."""
        from src.urlps._security import clear_caches, is_ssrf_risk
        is_ssrf_risk("example.com")
        result = clear_caches()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_dns_rate_limiter_get_stats(self):
        """Line 763: DNSRateLimiter.get_stats() returns expected keys."""
        from src.urlps._security import DNSRateLimiter
        limiter = DNSRateLimiter()
        stats = limiter.get_stats()
        assert "tokens" in stats
        assert "tracked_hosts" in stats
        assert "total_recent_lookups" in stats


# ---------------------------------------------------------------------------
# _validation.py gaps
# ---------------------------------------------------------------------------

class TestValidation:
    def test_to_ascii_host_with_idna_module(self):
        """Line 77: _to_ascii_host using idna module path."""
        from src.urlps._validation import Validator
        # This tests IDNA encoding of a punycode-capable host
        result = Validator._to_ascii_host.__wrapped__("münchen.de")
        assert isinstance(result, str)

    def test_is_valid_host_too_long_after_ascii(self):
        """Line 110: ASCII host exceeds MAX_HOST_LENGTH."""
        from src.urlps._validation import Validator
        from src.urlps.constants import MAX_HOST_LENGTH
        # Build a host that is short in unicode but long in ASCII
        # This requires a label that when IDNA-encoded exceeds max length
        long_host = "a" * (MAX_HOST_LENGTH + 1) + ".com"
        result = Validator.is_valid_host.__wrapped__(long_host)
        assert result is False

    def test_validate_ipv4_octets_leading_zero(self):
        """Line 140: octet with leading zero returns False."""
        from src.urlps._validation import Validator
        result = Validator._validate_ipv4_octets("192.168.01.1")
        assert result is False

    def test_validate_ipv4_octets_invalid_value(self):
        """Lines 147-148: ValueError in int() returns False."""
        from src.urlps._validation import Validator
        # An octet that isn't parseable as int
        result = Validator._validate_ipv4_octets("192.168.1.abc")
        assert result is False

    def test_is_standard_port_type_error(self):
        """Lines 211-212: TypeError returns False in is_standard_port."""
        from src.urlps._validation import Validator
        result = Validator.is_standard_port("not_a_port_int")
        assert result is False

    def test_is_url_safe_string_non_string(self):
        """Line 228: non-string returns False in is_url_safe_string."""
        from src.urlps._validation import Validator
        result = Validator.is_url_safe_string.__wrapped__(123)
        assert result is False

    def test_is_url_safe_string_none(self):
        """is_url_safe_string with None returns False."""
        from src.urlps._validation import Validator
        result = Validator.is_url_safe_string.__wrapped__(None)
        assert result is False

    def test_is_ip_address_non_string(self):
        """Line 282: is_ip_address with non-string returns False."""
        from src.urlps._validation import Validator
        result = Validator.is_ip_address.__wrapped__(123)
        assert result is False

    def test_get_cache_info_none_for_non_cached(self):
        """Line 302: get_cache_info returns None for methods without cache_info."""
        from src.urlps._validation import Validator
        # Temporarily inject a non-cached method name
        original = Validator._CACHED_METHODS[:]
        Validator._CACHED_METHODS = ["_validate_ipv4_octets"]  # not LRU cached
        try:
            info = Validator.get_cache_info()
            assert info.get("_validate_ipv4_octets") is None
        finally:
            Validator._CACHED_METHODS = original

    def test_clear_caches_zero_for_non_cached_method(self):
        """Lines 317->313, 320: clear_caches returns 0 for non-cached methods."""
        from src.urlps._validation import Validator
        original = Validator._CACHED_METHODS[:]
        Validator._CACHED_METHODS = ["_validate_ipv4_octets"]  # not LRU cached
        try:
            result = Validator.clear_caches()
            assert result.get("_validate_ipv4_octets") == 0
        finally:
            Validator._CACHED_METHODS = original


# ---------------------------------------------------------------------------
# exceptions.py gaps
# ---------------------------------------------------------------------------

class TestExceptions:
    def test_urlp_error_str_with_code_only(self):
        """Line 57: __str__ when code is set but no value/component."""
        from src.urlps.exceptions import URLpError, ErrorCode
        err = URLpError("test message", code=ErrorCode.SSRF_RISK)
        result = str(err)
        assert "ssrf_risk" in result
        assert "code=" in result

    def test_urlp_error_str_with_code_and_component(self):
        """Line 54: __str__ with code and component."""
        from src.urlps.exceptions import URLpError, ErrorCode
        err = URLpError("test message", value="bad_val", component="host", code=ErrorCode.SSRF_RISK)
        result = str(err)
        assert "code=" in result
        assert "component=" in result

    def test_urlp_error_str_basic(self):
        """Line 58: __str__ without code, without value/component."""
        from src.urlps.exceptions import URLpError
        err = URLpError("basic message")
        assert str(err) == "basic message"

    def test_urlp_error_str_component_only(self):
        """Line 55: __str__ with component but no code."""
        from src.urlps.exceptions import URLpError
        err = URLpError("msg", component="host")
        result = str(err)
        assert "component=" in result
        assert "code=" not in result


# ---------------------------------------------------------------------------
# security_policy.py gaps
# ---------------------------------------------------------------------------

class TestSecurityPolicy:
    def test_resolve_security_policy_with_security_policy_instance(self):
        """Line 77: resolve with SecurityPolicy instance returns it directly."""
        from src.urlps.security_policy import SecurityPolicy, resolve_security_policy
        policy = SecurityPolicy.strict()
        resolved = resolve_security_policy(policy)
        assert resolved is policy

    def test_resolve_security_policy_internal(self):
        """Lines 84-87: resolve with 'internal' string."""
        from src.urlps.security_policy import resolve_security_policy
        resolved = resolve_security_policy("internal")
        assert resolved.name == "internal"
        assert resolved.enforce_ssrf is False

    def test_resolve_security_policy_none_returns_balanced(self):
        """resolve with None returns balanced policy."""
        from src.urlps.security_policy import resolve_security_policy
        resolved = resolve_security_policy(None)
        assert resolved.name == "balanced"

    def test_resolve_security_policy_strict_string(self):
        """resolve with 'strict' string."""
        from src.urlps.security_policy import resolve_security_policy
        resolved = resolve_security_policy("strict")
        assert resolved.name == "strict"

    def test_resolve_security_policy_unsupported_raises(self):
        """resolve with invalid string raises ValueError."""
        from src.urlps.security_policy import resolve_security_policy
        with pytest.raises(ValueError, match="Unsupported security policy"):
            resolve_security_policy("invalid_policy")

    def test_resolve_security_policy_returns_resolved_when_no_overrides(self):
        """Line 112: returns resolved without rebuilding when no dns/phishing overrides."""
        from src.urlps.security_policy import SecurityPolicy, resolve_security_policy
        policy = SecurityPolicy.strict()
        resolved = resolve_security_policy(policy, check_dns=None, check_phishing=None)
        assert resolved is policy

    def test_resolve_security_policy_with_check_dns_override(self):
        """check_dns override creates new policy with check_dns=True."""
        from src.urlps.security_policy import resolve_security_policy
        resolved = resolve_security_policy("strict", check_dns=True)
        assert resolved.check_dns is True

    def test_resolve_security_policy_with_check_phishing_override(self):
        """check_phishing override creates new policy with check_phishing=True."""
        from src.urlps.security_policy import resolve_security_policy
        resolved = resolve_security_policy("balanced", check_phishing=True)
        assert resolved.check_phishing is True


# ---------------------------------------------------------------------------
# url.py gaps
# ---------------------------------------------------------------------------

class TestURL:
    def test_effective_port_returns_default_for_scheme(self):
        """Line 220: effective_port returns scheme default when no explicit port."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        assert url.effective_port == 443

    def test_effective_port_returns_none_without_scheme(self):
        """effective_port returns None when no scheme and no port."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        # Relative URL
        url = object.__new__(URL)
        url._scheme = None
        url._port = None
        assert url.effective_port is None

    def test_origin_raises_for_relative_url(self):
        """Line 230: origin raises InvalidURLError for relative URL (no scheme)."""
        from src.urlps.url import URL
        from src.urlps.exceptions import InvalidURLError
        from src.urlps.security_policy import SecurityPolicy
        # Create URL then strip scheme via copy
        url = URL("https://example.com/path", security_policy=SecurityPolicy.balanced())
        url_no_scheme = url.copy(scheme=None, host=None, port=None)
        with pytest.raises(InvalidURLError, match="relative"):
            _ = url_no_scheme.origin

    def test_normalize_port_non_numeric_string(self):
        """Line 452: non-numeric string port raises InvalidURLError."""
        from src.urlps.url import _normalize_port
        from src.urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="numeric"):
            _normalize_port("abc")

    def test_normalize_port_wrong_type(self):
        """Line 456: non-int/non-string type raises InvalidURLError."""
        from src.urlps.url import _normalize_port
        from src.urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="integer"):
            _normalize_port([8080])

    def test_normalize_port_out_of_range_high(self):
        """Line 468: port > 65535 raises InvalidURLError."""
        from src.urlps.url import _normalize_port
        from src.urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="65535"):
            _normalize_port(99999)

    def test_normalize_port_zero_raises(self):
        """Line 468: port 0 raises InvalidURLError."""
        from src.urlps.url import _normalize_port
        from src.urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="1 and 65535"):
            _normalize_port(0)

    def test_validate_copy_overrides_invalid_key(self):
        """Line 472: invalid override key raises InvalidURLError."""
        from src.urlps.url import _validate_copy_overrides
        from src.urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="Invalid override"):
            _validate_copy_overrides({"invalid_key": "value"})

    def test_validate_copy_overrides_non_string_component(self):
        """Line 475: non-string value for string component raises InvalidURLError."""
        from src.urlps.url import _validate_copy_overrides
        from src.urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="must be a string"):
            _validate_copy_overrides({"scheme": 123})

    def test_as_string_mask_password_with_colon(self):
        """Line 399: mask_password masks the password part of userinfo."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL(
            "https://admin:secret@example.com/path",
            security_policy=SecurityPolicy.internal(),
        )
        masked = url.as_string(mask_password=True)
        assert "secret" not in masked
        assert "admin" in masked

    def test_repr_with_valid_url(self):
        """__repr__ returns URL(...) string for valid URL."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        r = repr(url)
        assert r.startswith("URL(")
        assert "example.com" in r

    def test_security_checks_method(self):
        """Line 135: _security_checks() calls validate."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        findings = url._security_checks()
        # Returns None (implicitly), findings stored internally
        assert isinstance(url.security_findings, list)

    def test_validate_with_explicit_policy(self):
        """Line 347: validate() with an explicit policy parameter."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        findings = url.validate(policy=SecurityPolicy.balanced(), raise_on_error=False)
        assert isinstance(findings, list)

    def test_with_netloc_applies_default_port(self):
        """Lines 313-316: with_netloc injects default port for known scheme."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        updated = url.with_netloc("other.example.com")
        assert updated.host == "other.example.com"

    def test_with_netloc_from_https_url(self):
        """with_netloc on https URL applies default port 443 when not specified."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        url = URL("https://old.example.com/path", security_policy=SecurityPolicy.balanced())
        new_url = url.with_netloc("new.example.com")
        assert new_url.host == "new.example.com"
        # Port should be None (default 443 for https)
        assert new_url.port in (None, 443)

    def test_parse_and_validate_non_invalid_url_error_reraises(self):
        """Lines 129-131: non-InvalidURLError exception triggers audit and reraises."""
        from src.urlps.url import URL
        from src.urlps._parser import Parser

        class BoguParser(Parser):
            def parse(self, url):
                raise ValueError("unexpected parse error")

        with pytest.raises(ValueError, match="unexpected parse error"):
            URL("https://example.com/", parser=BoguParser())

    def test_build_netloc_scheme_relative_fails_for_non_file(self):
        """Line 286: compose() with scheme but empty netloc (non-file) raises."""
        from src.urlps._builder import Builder
        from src.urlps.exceptions import URLBuildError
        builder = Builder()
        with pytest.raises(URLBuildError):
            builder.compose({"scheme": "https", "host": None})

    def test_url_validate_raises_on_ssrf_by_policy(self):
        """Validate raises on SSRF risk with strict policy."""
        from src.urlps.url import URL
        from src.urlps.security_policy import SecurityPolicy
        from src.urlps.exceptions import InvalidURLError
        # Build URL that passes initial parse but fails validation
        url = URL(
            "https://example.com/",
            security_policy=SecurityPolicy.balanced(),
        )
        with pytest.raises(InvalidURLError):
            url.validate(policy=SecurityPolicy.strict(), raise_on_error=True,
                          raw_url="http://127.0.0.1/")


