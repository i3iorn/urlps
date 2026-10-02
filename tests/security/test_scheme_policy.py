"""The scheme allowlist is a policy setting with one rule (M4).

It used to be configured through mutable Parser state and duplicated in the
copy() validator, so validate(policy=...) could not ask about schemes and
nothing could allow only https. One rule (scheme_rejection) now serves the
parser, which applies it early, and the security pass.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from urlps import (
    ErrorCode,
    SecurityPolicy,
    SecurityPolicyError,
    UnsupportedSchemeError,
    URLParseError,
    parse_url,
    parse_url_local,
)
from urlps._security import collect_security_findings

HTTPS_ONLY = replace(SecurityPolicy.strict(), allowed_schemes={"https"})


def test_a_policy_can_narrow_the_allowed_schemes() -> None:
    assert parse_url("https://example.com/", policy=HTTPS_ONLY).scheme == "https"
    with pytest.raises(UnsupportedSchemeError) as excinfo:
        parse_url("http://example.com/", policy=HTTPS_ONLY)
    assert excinfo.value.code is ErrorCode.UNSUPPORTED_SCHEME


def test_validate_answers_scheme_questions_for_another_policy() -> None:
    url = parse_url("http://example.com/")
    codes = [finding.code for finding in url.validate(policy=HTTPS_ONLY)]
    assert codes == ["unsupported_scheme"]


def test_derived_urls_follow_the_policy_scheme_rule() -> None:
    url = parse_url("https://example.com/", policy=HTTPS_ONLY)
    with pytest.raises(UnsupportedSchemeError):
        url.with_scheme("http")


def test_a_policy_can_allow_a_scheme_outside_the_standard_set() -> None:
    policy = replace(SecurityPolicy.local(), allowed_schemes={"https", "file"})
    assert parse_url("file:///etc/hosts", policy=policy).scheme == "file"


def test_allow_custom_scheme_is_part_of_the_policy() -> None:
    url = parse_url_local("myapp://open/item", allow_custom_scheme=True)
    assert url.security_policy.allow_custom_scheme is True
    assert url.recognized_scheme is False
    assert url.with_path("/other").scheme == "myapp"


@pytest.mark.parametrize("schemes", ["https", ["https", 3], ["not a scheme"]])
def test_invalid_allowed_schemes_fail_at_construction(schemes: object) -> None:
    with pytest.raises(SecurityPolicyError):
        SecurityPolicy(name="bad", allowed_schemes=schemes)  # type: ignore[arg-type]


def test_allowed_schemes_are_lowercased() -> None:
    assert SecurityPolicy(name="x", allowed_schemes={"HTTPS"}).allowed_schemes == frozenset({"https"})


def test_unsafe_schemes_raise_a_parse_error_as_in_1_1() -> None:
    """1.1 raised URLParseError for javascript:; UnsupportedSchemeError is now one."""
    with pytest.raises(URLParseError) as excinfo:
        parse_url("javascript:alert(1)")
    assert isinstance(excinfo.value, UnsupportedSchemeError)
    assert excinfo.value.code is ErrorCode.UNSAFE_SCHEME


def test_custom_schemes_must_still_be_well_formed() -> None:
    with pytest.raises(URLParseError, match="Invalid URL scheme"):
        parse_url("a_b://example.com/", allow_custom_scheme=True)


def test_findings_are_reported_in_a_fixed_order() -> None:
    """The first blocking finding decides the exception, so the order is part of the contract."""
    policy = replace(HTTPS_ONLY, block_dangerous_ports=True)
    codes = [f.code for f in collect_security_findings("ftp://user:pw@127.0.0.1:22/a/../%252e", policy=policy)]
    assert codes == [
        "unsupported_scheme",
        "double_encoding",
        "ssrf_risk",
        "path_traversal",
        "credentials_in_url",
        "dangerous_port",
    ]
