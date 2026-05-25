from urlps._builder import Builder
from urlps._validation import Validator


def test_is_valid_ipv6_various():
    # valid bracketed IPv6 literal
    assert Validator.is_valid_ipv6("[2001:db8::1]")
    # missing brackets should be invalid for literal
    assert not Validator.is_valid_ipv6("2001:db8::1")
    # invalid characters
    assert not Validator.is_valid_ipv6("[2001:db8::zz]")
    # empty
    assert not Validator.is_valid_ipv6("")
    # non-string
    assert not Validator.is_valid_ipv6(123)  # type: ignore[arg-type]


def test_path_and_query_percent_encoding_and_validator():
    b = Builder()
    # path segments with spaces should be percent-encoded by Builder
    raw_path = "/a b/c%25d"
    normalized = b.normalize_path(raw_path)
    # ensure percent-encoding is present and Validator accepts it
    assert "%20" in normalized or "%25" in normalized
    assert Validator.is_valid_path(normalized)

    # query serialization should percent-encode keys/values
    pairs = [("key name", "value/with/slash"), ("enc%", "v%")]
    q = b.serialize_query(pairs)
    # percent-encoded tokens should be present and Validator accepts them
    assert "%20" in q or "%2F" in q or "%25" in q
    # split key/value tokens and validate via Validator
    for chunk in q.split("&"):
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            assert Validator.is_valid_query_param(k)
            assert Validator.is_valid_query_param(v)
        else:
            assert Validator.is_valid_query_param(chunk)

