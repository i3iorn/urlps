import pytest

from urlps._parser import Parser
from urlps._validation import Validator


def test_parser_accepts_compressed_ipv6_literals():
    p = Parser()
    urls = [
        "http://[::1]/",
        "http://[2001:db8::1]/",
        "http://[::ffff:192.0.2.1]/",
        "http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]/",
    ]
    for u in urls:
        parsed = p.parse(u)
        assert parsed["host"].startswith("[") and parsed["host"].endswith("]")


def test_validator_ipv6_bracketed_and_non_bracketed():
    assert Validator.is_valid_ipv6("[::1]")
    assert Validator.is_valid_ipv6("[2001:db8::1]")
    assert not Validator.is_valid_ipv6("::1")


def test_validator_accepts_percent_encoded_zone_index():
    # RFC allows zone ids in literals, but in URLs the '%' must be percent-encoded as %25
    assert Validator.is_valid_ipv6("[fe80::1%25en0]")
    assert not Validator.is_valid_ipv6("[fe80::1%en0]")  # raw % not allowed


def test_validator_rejects_invalid_ipv6_literals():
    assert not Validator.is_valid_ipv6("[2001:db8::zz]")
    assert not Validator.is_valid_ipv6("[::1]extra")


def test_parser_accepts_zone_index_literals_when_percent_encoded():
    p = Parser()
    parsed = p.parse("http://[fe80::1%25en0]/")
    assert parsed["host"] == "[fe80::1%25en0]"


def test_parser_rejects_unclosed_bracket():
    p = Parser()
    with pytest.raises(Exception):
        p.parse("http://[2001:db8::1/path")

