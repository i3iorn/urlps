"""
RFC 3986 §6.2.2 syntax-based normalization.

The negative half of this file matters more than the positive half. Decoding a
percent-escape that happens to be a *delimiter* silently changes what the URL
means -- turning ``%2F`` into ``/`` invents a path segment, which is the
classic traversal-via-normalization vulnerability. So every assertion that
something is *left alone* is a security test, not a style test.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from urlps import parse_url
from urlps._normalize import normalize_host, normalize_percent_encoding

ALL_POLICIES = ["strict", "balanced", "internal", "local"]


class TestNormalizeHost:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("EXAMPLE.COM", "example.com"),
            ("ExAmPlE.CoM", "example.com"),
            ("example.com.", "example.com"),
            ("EXAMPLE.COM.", "example.com"),
            ("example.com", "example.com"),
            ("", ""),
            (".", "."),  # bare root label: nothing to strip
        ],
    )
    def test_regname(self, raw: str, expected: str) -> None:
        assert normalize_host(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("[0:0:0:0:0:0:0:1]", "[::1]"),
            ("[2001:0DB8::0001]", "[2001:db8::1]"),
            ("[::1]", "[::1]"),
            ("[::FFFF:127.0.0.1]", "[::ffff:127.0.0.1]"),
        ],
    )
    def test_ipv6_literal(self, raw: str, expected: str) -> None:
        assert normalize_host(raw) == expected

    def test_ipv6_zone_is_preserved_byte_exact(self) -> None:
        # The zone ID is inspected by is_malicious_ipv6_zone_id; rewriting it
        # here would hide the very text that check needs to see.
        assert normalize_host("[fe80:0:0:0:0:0:0:1%eth0]") == "[fe80::1%eth0]"
        assert normalize_host("[fe80::1%25eth0]") == "[fe80::1%25eth0]"

    def test_unparseable_literal_is_not_rewritten(self) -> None:
        # Validation reports it elsewhere; masking it here would be worse.
        assert normalize_host("[not-an-address]") == "[not-an-address]"

    @pytest.mark.parametrize("raw", ["EXAMPLE.COM.", "[0:0:0:0:0:0:0:1]", "example.com", ""])
    def test_idempotent(self, raw: str) -> None:
        once = normalize_host(raw)
        assert normalize_host(once) == once


class TestNormalizePercentEncoding:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("%7E", "~"),
            ("%7e", "~"),
            ("%41", "A"),
            ("%61", "a"),
            ("%30", "0"),
            ("%2D", "-"),
            ("%2E", "."),
            ("%5F", "_"),
        ],
    )
    def test_unreserved_escapes_are_decoded(self, raw: str, expected: str) -> None:
        assert normalize_percent_encoding(raw) == expected

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("%2f", "%2F"),
            ("%3f", "%3F"),
            ("%23", "%23"),
            ("%3a", "%3A"),
            ("%ff", "%FF"),
        ],
    )
    def test_reserved_escape_hex_is_uppercased_but_not_decoded(self, raw: str, expected: str) -> None:
        assert normalize_percent_encoding(raw) == expected

    @pytest.mark.parametrize(
        "escape",
        ["%2F", "%3F", "%23", "%26", "%3D", "%40", "%3A", "%2f", "%3f"],
    )
    def test_delimiters_are_never_decoded(self, escape: str) -> None:
        """The security-critical assertion: decoding these changes URL structure."""
        out = normalize_percent_encoding(escape)
        assert out.startswith("%")
        assert len(out) == 3

    def test_non_escape_text_is_untouched(self) -> None:
        assert normalize_percent_encoding("plain/text?a=b&c=d") == "plain/text?a=b&c=d"

    def test_malformed_escape_is_untouched(self) -> None:
        for raw in ("%", "%2", "%ZZ", "%G0", "100%"):
            assert normalize_percent_encoding(raw) == raw

    @pytest.mark.parametrize("raw", ["%7e", "%2f", "a%41b%2Fc", "plain"])
    def test_idempotent(self, raw: str) -> None:
        once = normalize_percent_encoding(raw)
        assert normalize_percent_encoding(once) == once


class TestAppliedThroughParse:
    @pytest.mark.parametrize("policy", ALL_POLICIES)
    def test_components_and_serialization_agree(self, policy: str) -> None:
        url = parse_url("http://EXAMPLE.COM./a%2fb?q=%7e#%7e", policy=policy)
        assert url.host == "example.com"
        assert url.path == "/a%2Fb"
        assert url.query == "q=~"
        assert url.fragment == "~"
        assert str(url) == "http://example.com/a%2Fb?q=~#~"


class TestNotNormalized:
    """Things that must survive byte-exact. Each one would be a bug to 'fix'."""

    def test_path_case_is_preserved(self) -> None:
        # Origin servers are overwhelmingly case-sensitive on paths.
        assert parse_url("http://example.com/PaTh/MiXeD", policy="local").path == "/PaTh/MiXeD"

    def test_query_key_and_value_case_are_preserved(self) -> None:
        url = parse_url("http://example.com/?KeY=VaLuE&X=Y", policy="local")
        assert url.query == "KeY=VaLuE&X=Y"

    def test_query_parameter_order_is_preserved(self) -> None:
        # Signature schemes (AWS SigV4, webhook HMACs) depend on this.
        url = parse_url("http://example.com/?z=1&a=2&m=3", policy="local")
        assert url.query == "z=1&a=2&m=3"

    def test_userinfo_is_preserved(self) -> None:
        url = parse_url("http://User:P%40ss@example.com/", policy="local")
        assert url.userinfo == "User:P%40ss"

    def test_encoded_slash_does_not_become_a_path_segment(self) -> None:
        url = parse_url("http://example.com/a%2F..%2Fb", policy="local")
        assert url.path == "/a%2F..%2Fb"
        assert "/../" not in url.path

    def test_fragment_content_case_is_preserved(self) -> None:
        assert parse_url("http://example.com/#SecTion", policy="local").fragment == "SecTion"


class TestIdempotenceProperty:
    @settings(max_examples=200, deadline=None)
    @given(
        host=st.sampled_from(["example.com", "EXAMPLE.COM", "Example.Com.", "[0:0:0:0:0:0:0:1]", "[::1]"]),
        path=st.sampled_from(["/", "/a", "/a/b", "/a%2fb", "/%7Eu", "/a/./b"]),
    )
    def test_reparsing_is_a_fixed_point(self, host: str, path: str) -> None:
        once = str(parse_url(f"http://{host}{path}", policy="local"))
        assert str(parse_url(once, policy="local")) == once
