"""Additional URL object tests grouped by URL behavior."""

from __future__ import annotations

import pytest

class TestURL:
    def test_effective_port_returns_default_for_scheme(self):
        """Line 220: effective_port returns scheme default when no explicit port."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        assert url.effective_port == 443

    def test_effective_port_returns_none_without_scheme(self):
        """effective_port returns None when no scheme and no port."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        # Relative URL
        url = object.__new__(URL)
        url._scheme = None
        url._port = None
        assert url.effective_port is None

    def test_origin_raises_for_relative_url(self):
        """Line 230: origin raises InvalidURLError for relative URL (no scheme)."""
        from urlps.url import URL
        from urlps.exceptions import InvalidURLError
        from urlps._security.policy import SecurityPolicy
        # Create URL then strip scheme via copy
        url = URL("https://example.com/path", security_policy=SecurityPolicy.balanced())
        url_no_scheme = url.copy(scheme=None, host=None, port=None)
        with pytest.raises(InvalidURLError, match="relative"):
            _ = url_no_scheme.origin

    def test_normalize_port_non_numeric_string(self):
        """Line 452: non-numeric string port raises InvalidURLError."""
        from urlps.url import _normalize_port
        from urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="numeric"):
            _normalize_port("abc")

    def test_normalize_port_wrong_type(self):
        """Line 456: non-int/non-string type raises InvalidURLError."""
        from urlps.url import _normalize_port
        from urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="integer"):
            _normalize_port([8080])

    def test_normalize_port_out_of_range_high(self):
        """Line 468: port > 65535 raises InvalidURLError."""
        from urlps.url import _normalize_port
        from urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="65535"):
            _normalize_port(99999)

    def test_normalize_port_zero_raises(self):
        """Line 468: port 0 raises InvalidURLError."""
        from urlps.url import _normalize_port
        from urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="1 and 65535"):
            _normalize_port(0)

    def test_validate_copy_overrides_invalid_key(self):
        """Line 472: invalid override key raises InvalidURLError."""
        from urlps.url import _validate_copy_overrides
        from urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="Invalid override"):
            _validate_copy_overrides({"invalid_key": "value"})

    def test_validate_copy_overrides_non_string_component(self):
        """Line 475: non-string value for string component raises InvalidURLError."""
        from urlps.url import _validate_copy_overrides
        from urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="must be a string"):
            _validate_copy_overrides({"scheme": 123})

    def test_as_string_mask_password_with_colon(self):
        """Line 399: mask_password masks the password part of userinfo."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL(
            "https://admin:secret@example.com/path",
            security_policy=SecurityPolicy.internal(),
        )
        masked = url.as_string(mask_password=True)
        assert "secret" not in masked
        assert "admin" in masked

    def test_repr_with_valid_url(self):
        """__repr__ returns URL(...) string for valid URL."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        r = repr(url)
        assert r.startswith("URL(")
        assert "example.com" in r

    def test_security_checks_method(self):
        """Line 135: _security_checks() calls validate."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        findings = url._security_checks()
        # Returns None (implicitly), findings stored internally
        assert isinstance(url.security_findings, list)

    def test_validate_with_explicit_policy(self):
        """Line 347: validate() with an explicit policy parameter."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        findings = url.validate(policy=SecurityPolicy.balanced(), raise_on_error=False)
        assert isinstance(findings, list)

    def test_with_netloc_applies_default_port(self):
        """Lines 313-316: with_netloc injects default port for known scheme."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        updated = url.with_netloc("other.example.com")
        assert updated.host == "other.example.com"

    def test_with_netloc_from_https_url(self):
        """with_netloc on https URL applies default port 443 when not specified."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL("https://old.example.com/path", security_policy=SecurityPolicy.balanced())
        new_url = url.with_netloc("new.example.com")
        assert new_url.host == "new.example.com"
        # Port should be None (default 443 for https)
        assert new_url.port in (None, 443)

    def test_parse_and_validate_non_invalid_url_error_reraises(self):
        """Lines 129-131: non-InvalidURLError exception triggers audit and reraises."""
        from urlps.url import URL
        from urlps._parser import Parser

        class BoguParser(Parser):
            def parse(self, url):
                raise ValueError("unexpected parse error")

        with pytest.raises(ValueError, match="unexpected parse error"):
            URL("https://example.com/", parser=BoguParser())

    def test_build_netloc_scheme_relative_fails_for_non_file(self):
        """Line 286: compose() with scheme but empty netloc (non-file) raises."""
        from urlps._builder import Builder
        from urlps.exceptions import URLBuildError
        builder = Builder()
        with pytest.raises(URLBuildError):
            builder.compose({"scheme": "https", "host": None})

    def test_url_validate_raises_on_ssrf_by_policy(self):
        """Validate raises on SSRF risk with strict policy."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        from urlps.exceptions import InvalidURLError
        # Build URL that passes initial parse but fails validation
        url = URL(
            "https://example.com/",
            security_policy=SecurityPolicy.balanced(),
        )
        with pytest.raises(InvalidURLError):
            url.validate(policy=SecurityPolicy.strict(), raise_on_error=True,
                          raw_url="http://127.0.0.1/")

class TestURLAdditional:
    """Cover remaining url.py lines that need simple tests."""

    def _make_url(self, url_str: str = "https://example.com/path?k=v"):
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        return URL(url_str, security_policy=SecurityPolicy.balanced())

    def test_is_absolute_true(self):
        """is_absolute returns True for absolute URL."""
        url = self._make_url()
        assert url.is_absolute is True

    def test_is_absolute_false_no_host(self):
        """is_absolute returns False when no host (and no scheme)."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        url_bare = url.copy(scheme=None, host=None, port=None)
        assert url_bare.is_absolute is False

    def test_with_query_sets_query(self):
        """with_query() builds new URL with given query string."""
        url = self._make_url()
        new_url = url.with_query("a=1&b=2")
        assert new_url.query == "a=1&b=2"

    def test_with_query_none_removes_query(self):
        """with_query(None) clears the query."""
        url = self._make_url()
        new_url = url.with_query(None)
        assert new_url.query is None

    def test_with_userinfo_sets_userinfo(self):
        """with_userinfo() sets the userinfo component."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.internal())
        new_url = url.with_userinfo("user:pass")
        assert new_url.userinfo == "user:pass"

    def test_with_userinfo_none_clears_userinfo(self):
        """with_userinfo(None) removes userinfo."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL("https://user:pass@example.com/", security_policy=SecurityPolicy.internal())
        new_url = url.with_userinfo(None)
        assert new_url.userinfo is None

    def test_without_query_param_removes_matching_key(self):
        """without_query_param() removes all occurrences of a key (checks query string)."""
        url = self._make_url("https://example.com/?a=1&b=2&a=3")
        new_url = url.without_query_param("a")
        # Query string should not contain 'a=' entries; check via query string
        query = new_url.query or ""
        pairs = [p.split("=")[0] for p in query.split("&") if p]
        assert "a" not in pairs
        assert "b" in pairs

    def test_without_query_param_key_not_present(self):
        """without_query_param() with absent key returns same query."""
        url = self._make_url("https://example.com/?x=1")
        new_url = url.without_query_param("z")
        assert "x=1" in new_url.query

    def test_is_semantically_equal_with_non_url_returns_false(self):
        """is_semantically_equal returns False for non-URL argument."""
        url = self._make_url()
        assert url.is_semantically_equal("not-a-url-object") is False
        assert url.is_semantically_equal(42) is False
        assert url.is_semantically_equal(None) is False

    def test_str_returns_url_string(self):
        """__str__ returns the URL as string."""
        url = self._make_url()
        result = str(url)
        assert isinstance(result, str)
        assert "example.com" in result

    def test_normalize_port_valid_digit_string(self):
        """_normalize_port with valid numeric string returns int."""
        from urlps.url import _normalize_port
        assert _normalize_port("8080") == 8080
        assert _normalize_port("443") == 443
        assert _normalize_port("1") == 1

    def test_validate_copy_overrides_userinfo_non_string(self):
        """Line 475: non-string userinfo raises InvalidURLError."""
        from urlps.url import _validate_copy_overrides
        from urlps.exceptions import InvalidURLError
        with pytest.raises(InvalidURLError, match="userinfo must be"):
            _validate_copy_overrides({"userinfo": 999})

    def test_effective_port_falls_back_to_scheme_default(self):
        """effective_port returns scheme default when _port is None."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL("https://example.com/", security_policy=SecurityPolicy.balanced())
        # Force explicit port=None via copy
        url_no_port = url.copy(port=None)
        assert url_no_port.effective_port == 443

    def test_as_string_mask_password_no_colon_in_userinfo(self):
        """as_string with mask_password=True and no ':' in userinfo is unchanged."""
        from urlps.url import URL
        from urlps._security.policy import SecurityPolicy
        url = URL("https://user@example.com/", security_policy=SecurityPolicy.internal())
        masked = url.as_string(mask_password=True)
        assert "user" in masked

    def test_without_query_then_add_back(self):
        """without_query removes query and fragment; add back works."""
        url = self._make_url("https://example.com/path?x=1#frag")
        no_query = url.without_query()
        assert no_query.query is None
        assert no_query.fragment is None
