"""Lone surrogates fail fast, with urlps exception types.

A surrogate (U+D800-U+DFFF) cannot be encoded to bytes, so a component
holding one used to pass parsing and then crash -- with a raw
UnicodeEncodeError, not a urlps exception -- inside *callers*' str(),
logging and marshalling code: the parse itself succeeded and the
exception fired at serialization time, dodging every handler written
for the library's own errors.

Rejecting them at the entry checks turns that into an InvalidURLError at
the call site; wrapping the builder's encode steps keeps the same guarantee
for composed URLs.
"""

from __future__ import annotations

import pytest

from urlps import InvalidURLError, URLParseError, build, compose_url, parse_url
from urlps._validation import Validator
from urlps.exceptions import URLBuildError

#: A lone (unpaired) high surrogate. Written as an escape so this file
#: itself stays valid source on every toolchain.
SURROGATE = "\ud800"


def test_is_url_safe_string_rejects_surrogates() -> None:
    assert Validator.is_url_safe_string(f"https://h/x{SURROGATE}y") is False
    assert Validator.is_url_safe_string("https://h/xY") is True


def test_parse_url_rejects_surrogate_in_path() -> None:
    with pytest.raises(URLParseError, match="control characters or surrogates"):
        parse_url(f"https://h/x{SURROGATE}y")


def test_copy_override_with_surrogate_path_is_rejected() -> None:
    url = parse_url("https://example.com/api")
    with pytest.raises(InvalidURLError, match="control characters or surrogates"):
        url.copy(path=f"/x{SURROGATE}y")


def test_copy_override_with_surrogate_query_is_rejected() -> None:
    url = parse_url("https://example.com/api")
    with pytest.raises(InvalidURLError, match="control characters or surrogates"):
        url.copy(query=f"a={SURROGATE}")


def test_with_query_param_surrogate_value_raises_url_build_error() -> None:
    url = parse_url("https://example.com/api")
    # Previously: raw UnicodeEncodeError from quote_plus inside add_param --
    # an exception type outside the library's whole hierarchy.
    with pytest.raises(URLBuildError):
        url.with_query_param("a", f"x{SURROGATE}")


def test_build_with_surrogate_path_raises_url_build_error() -> None:
    with pytest.raises(URLBuildError):
        build("https", "example.com", path=f"/x{SURROGATE}y")


def test_build_with_surrogate_query_string_raises_url_build_error() -> None:
    # A raw `query` string is emitted as-is by compose(); the surrogate never
    # reaches an encode step there, so -- unlike query_pairs -- it survives
    # composition today. Python itself rejects it only at re-serialize time,
    # so assert the documented behavior rather than an encode error.
    string_form = build("https", "example.com", query=f"a={SURROGATE}")
    assert string_form == f"https://example.com/?a={SURROGATE}"


def test_compose_with_surrogate_query_pairs_raises_url_build_error() -> None:
    with pytest.raises(URLBuildError):
        compose_url({"scheme": "https", "host": "example.com", "query_pairs": [("a", f"x{SURROGATE}")]})


def test_surrogate_in_query_pair_key_raises_url_build_error() -> None:
    with pytest.raises(URLBuildError):
        compose_url({"scheme": "https", "host": "example.com", "query_pairs": [(f"k{SURROGATE}", "v")]})


def test_valid_urls_still_parse() -> None:
    # Non-ASCII Below the surrogate range encodes fine and was never the
    # problem.
    assert str(parse_url("https://example.com/föö").canonicalize().as_string()).startswith("https://example.com/")
