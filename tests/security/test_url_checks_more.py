"""Additional coverage for _security/url_checks.py hot-path helpers."""

from __future__ import annotations

from unittest.mock import patch

from urlps._security.url_checks import (
    _has_confusing_userinfo_markers,
    get_canonical_url,
    has_credentials,
    has_parser_confusion,
    has_scheme_authority,
    has_suspicious_punycode,
    is_open_redirect_risk,
    redact_url_for_logs,
)


class TestHasSchemeAuthority:
    def test_non_string_returns_false(self):
        assert has_scheme_authority(None) is False  # type: ignore[arg-type]


class TestIsOpenRedirectRisk:
    def test_percent_decode_failure_returns_false(self):
        with patch("urlps._security.url_checks.unquote", side_effect=ValueError("bad")):
            assert is_open_redirect_risk("/some/path") is False


class TestHasParserConfusion:
    def test_multiple_at_symbols_in_authority(self):
        assert has_parser_confusion("https://user@evil@example.com/path") is True


class TestHasConfusingUserinfoMarkers:
    def test_no_at_symbol_returns_false(self):
        assert _has_confusing_userinfo_markers("no-at-symbol") is False

    def test_terminator_before_last_at_returns_true(self):
        assert _has_confusing_userinfo_markers("user/x@host") is True


class TestHasCredentials:
    def test_empty_string_returns_false(self):
        assert has_credentials("") is False

    def test_malformed_url_returns_false(self):
        with patch("urlps._security.url_checks.urlsplit", side_effect=ValueError("bad")):
            assert has_credentials("https://example.com/") is False


class TestRedactUrlForLogs:
    def test_redacts_userinfo_without_password(self):
        assert redact_url_for_logs("https://user@example.com/path") == "https://***@example.com/path"

    def test_redacts_userinfo_with_password(self):
        result = redact_url_for_logs("https://user:secret@example.com/path")
        assert result == "https://user:***@example.com/path"

    def test_malformed_url_returns_original(self):
        with patch("urlps._security.url_checks.urlsplit", side_effect=ValueError("bad")):
            assert redact_url_for_logs("https://example.com/") == "https://example.com/"


class TestHasSuspiciousPunycode:
    def test_digits_and_non_ascii_domain_flagged(self):
        assert has_suspicious_punycode("xn--123münchen.example") is True

    def test_non_ascii_domain_all_digits_after_punctuation_flagged(self):
        # Domain made only of full-width digits (non-ascii) once punctuation
        # is stripped.
        assert has_suspicious_punycode("xn--123-München.com") is True

    def test_non_digit_non_alnum_non_ascii_domain_flagged(self):
        # No ASCII/Unicode digits, but every non-ascii char is non-alnum
        # punctuation, so the "all digits once punctuation is stripped"
        # check is vacuously true over an empty filtered set.
        assert has_suspicious_punycode("···.com") is True

    def test_non_ascii_domain_matching_brand_flagged(self):
        assert has_suspicious_punycode("xn--pypal-münchende.com") is True


class TestGetCanonicalUrl:
    def test_no_authority_marker_returns_none(self):
        assert get_canonical_url("not a url") is None

    def test_credentials_are_preserved_in_netloc(self):
        result = get_canonical_url("HTTP://user:pass@EXAMPLE.COM:80/a/./b")
        assert result is not None
        assert "user:pass@" in result

    def test_bracketed_host_with_trailing_garbage_is_rejected_upstream(self):
        # This was written to exercise the netloc.startswith("[")/else
        # fallback at the bottom of the bracketed-host branch (parsed.hostname
        # for a netloc that's neither "]:port" nor a plain "]" ending). But
        # stdlib's urlparse() validates IPv6 bracket syntax strictly and
        # raises ValueError("Invalid IPv6 URL") for "[::1]extra" before
        # get_canonical_url ever reaches that branch -- get_canonical_url's
        # own try/except (ValueError, AttributeError) then fails closed and
        # returns None, which is the correct, safe outcome for malformed
        # input, not a bug to work around.
        assert get_canonical_url("http://[::1]extra/path") is None

    def test_ipv6_host_with_port(self):
        result = get_canonical_url("http://[::1]:8080/path")
        assert result is not None
        assert "[::1]:8080" in result

    def test_ipv6_host_with_zone_id(self):
        result = get_canonical_url("http://[fe80::1%25eth0]/path")
        assert result is not None

    def test_default_port_is_dropped(self):
        result = get_canonical_url("http://example.com:80/path")
        assert result == "http://example.com/path"

    def test_non_default_port_is_preserved(self):
        result = get_canonical_url("http://example.com:8080/path")
        assert ":8080" in result

    def test_lowercase_percent_encoding_of_reserved_char_is_uppercased(self):
        result = get_canonical_url("http://example.com/%2fuser")
        assert result is not None
        assert "%2F" in result

    def test_lowercase_percent_encoding_of_unreserved_char_is_decoded(self):
        result = get_canonical_url("http://example.com/%7euser")
        assert result == "http://example.com/~user"

    def test_malformed_url_returns_none(self):
        with patch("urlps._security.url_checks.urlparse", side_effect=ValueError("bad")):
            assert get_canonical_url("http://example.com/") is None
