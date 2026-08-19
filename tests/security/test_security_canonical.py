"""
Canonicalization is applied, not merely detected.

Before 1.0 this was a validation *gate*: `require_canonical` rejected URLs
that differed from canonical form, and turning the gate off (the shipped
`balanced` preset) handed back an un-normalized host. That combination was
both user-hostile and a security bug -- a caller's `url.host in ALLOWLIST`
check silently failed to match "EXAMPLE.COM" or "evil.com.".

1.0 normalizes instead. These tests assert the resulting invariant, which is
strictly stronger than the old detector: **you cannot obtain a non-canonical
URL object from urlps by any route or under any policy.** Equal resources
therefore compare equal, which is what the security scenarios at the bottom
of this file actually depend on.
"""

from __future__ import annotations

import pytest

from urlps import SecurityPolicy, parse_url

ALL_POLICIES = ["strict", "balanced", "internal", "local"]


def _host(url: str, policy: str = "strict") -> str:
    return parse_url(url, policy=policy).host


class TestHostNormalization:
    """The security-critical half: host case and the trailing root dot."""

    @pytest.mark.parametrize("policy", ALL_POLICIES)
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("http://EXAMPLE.COM/", "example.com"),
            ("http://ExAmPlE.CoM/", "example.com"),
            ("http://example.com./", "example.com"),
            ("http://EXAMPLE.COM./", "example.com"),
            ("http://sub.EXAMPLE.com/", "sub.example.com"),
        ],
    )
    def test_host_is_canonical_under_every_policy(self, raw: str, expected: str, policy: str) -> None:
        # Under *every* policy, including the permissive ones -- normalization
        # is not a security check that a policy can switch off.
        assert _host(raw, policy) == expected

    @pytest.mark.parametrize("policy", ALL_POLICIES)
    def test_allowlist_comparison_is_reliable(self, policy: str) -> None:
        allowlist = {"example.com"}
        for raw in ("http://EXAMPLE.COM/", "http://Example.Com./", "http://example.com/"):
            assert _host(raw, policy) in allowlist

    @pytest.mark.parametrize("policy", ALL_POLICIES)
    def test_blocklist_comparison_is_reliable(self, policy: str) -> None:
        blocklist = {"evil.com"}
        for raw in ("http://EVIL.COM/", "http://evil.com./", "http://EvIl.CoM./"):
            assert _host(raw, policy) in blocklist


class TestSchemeAndPort:
    def test_scheme_is_lowercased(self) -> None:
        assert parse_url("HTTP://example.com/").scheme == "http"
        assert parse_url("HtTpS://example.com/").scheme == "https"

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("http://example.com:80/", "http://example.com/"),
            ("https://example.com:443/", "https://example.com/"),
            ("ws://example.com:80/", "ws://example.com/"),
            ("wss://example.com:443/", "wss://example.com/"),
        ],
    )
    def test_default_port_is_dropped_from_serialization(self, raw: str, expected: str) -> None:
        assert str(parse_url(raw)) == expected

    def test_non_default_port_is_preserved(self) -> None:
        assert str(parse_url("http://example.com:8080/")) == "http://example.com:8080/"


class TestPathNormalization:
    def test_dot_segment_is_resolved(self) -> None:
        assert parse_url("http://example.com/a/./b").path == "/a/b"

    def test_already_normal_path_is_untouched(self) -> None:
        assert parse_url("http://example.com/a/b").path == "/a/b"

    def test_traversal_is_still_rejected_not_silently_resolved(self) -> None:
        # Normalizing "." must not be confused with tolerating "..".
        from urlps import InvalidURLError

        with pytest.raises(InvalidURLError):
            parse_url("http://example.com/a/../b")


class TestIPv6Canonicalization:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("http://[0:0:0:0:0:0:0:1]/", "[::1]"),
            ("http://[2001:0DB8::0001]/", "[2001:db8::1]"),
            ("http://[2001:db8:0:0:0:0:0:1]/", "[2001:db8::1]"),
            ("http://[::1]/", "[::1]"),
        ],
    )
    def test_ipv6_literal_is_canonical(self, raw: str, expected: str) -> None:
        assert _host(raw, "local") == expected

    def test_two_spellings_of_one_address_compare_equal(self) -> None:
        a = parse_url("http://[0:0:0:0:0:0:0:1]/", policy="local")
        b = parse_url("http://[::1]/", policy="local")
        assert a.host == b.host


class TestIdempotence:
    """Normalization runs on both the parse and build paths, so it must be idempotent."""

    @pytest.mark.parametrize(
        "raw",
        [
            "http://EXAMPLE.COM./a/./b?x=1#f",
            "https://example.com:443/%7Euser",
            "http://[0:0:0:0:0:0:0:1]:8080/p",
            "http://example.com/a%2Fb",
        ],
    )
    def test_reparsing_is_a_fixed_point(self, raw: str) -> None:
        once = str(parse_url(raw, policy="local"))
        twice = str(parse_url(once, policy="local"))
        assert once == twice

    def test_derived_urls_stay_canonical(self) -> None:
        # with_*() goes through copy(), a different code path than parse.
        u = parse_url("http://example.com/", policy="local")
        assert u.with_host("EXAMPLE.COM.").host == "example.com"
        assert u.with_host("[0:0:0:0:0:0:0:1]").host == "[::1]"


class TestSecurityImplications:
    """
    The scenarios that motivated canonicalization in the first place. Each one
    used to require the caller to remember to canonicalize; now it holds by
    construction.
    """

    def test_cache_key_collision_is_impossible(self) -> None:
        urls = [
            "http://example.com/path",
            "HTTP://EXAMPLE.COM/path",
            "http://example.com:80/path",
            "http://example.com/./path",
            "http://example.com./path",
        ]
        assert len({str(parse_url(u)) for u in urls}) == 1

    def test_access_control_bypass_is_impossible(self) -> None:
        protected = str(parse_url("http://example.com/admin"))
        for variant in ("http://example.com/./admin", "HTTP://example.com/admin", "http://EXAMPLE.COM./admin"):
            assert str(parse_url(variant)) == protected

    def test_web_crawler_deduplication(self) -> None:
        urls = [
            "http://example.com/page",
            "HTTP://example.com/page",
            "http://EXAMPLE.COM/page",
            "http://example.com:80/page",
            "http://example.com/./page",
        ]
        assert len({str(parse_url(u)) for u in urls}) == 1

    def test_url_equality_follows_canonical_form(self) -> None:
        assert parse_url("HTTP://EXAMPLE.COM:80/p") == parse_url("http://example.com/p")
        assert hash(parse_url("HTTP://EXAMPLE.COM:80/p")) == hash(parse_url("http://example.com/p"))


class TestPolicyFlagRemoved:
    def test_require_canonical_flag_no_longer_exists(self) -> None:
        # Must fail loudly: silently ignoring it would leave callers believing
        # a check is still running.
        with pytest.raises(TypeError):
            SecurityPolicy(name="legacy", require_canonical=True)  # type: ignore[call-arg]
