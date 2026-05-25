import pytest

from urlps._validation import Validator
from urlps._parser import Parser
from urlps import URL


def test_idna_unicode_roundtrip_host():
    # Unicode domain for 'пример.рф' (Russian) -> punycode xn--e1afmkfd.xn--p1ai
    unicode_host = "пример.рф"
    # Parser should accept unicode host by IDNA-encoding; validate via Validator on ASCII form
    parser = Parser()
    parsed = parser.parse(f"http://{unicode_host}/")
    assert parsed["host"] == "xn--e1afmkfd.xn--p1ai"
    # URL class should preserve host and rebuild string
    u = URL(f"http://{unicode_host}/")
    assert u.host == "xn--e1afmkfd.xn--p1ai"
    assert "xn--e1afmkfd" in u.as_string()


def test_is_valid_ipv4_edge_cases():
    # RFC 3986 recommends strict decimal - reject leading zeros
    assert not Validator.is_valid_ipv4("192.168.001.001")
    # octal/hex strings should be rejected because regex only allows digits
    assert not Validator.is_valid_ipv4("0xC0.0xA8.0x01.0x01")
    # values out of range
    assert not Validator.is_valid_ipv4("256.0.0.1")
    assert not Validator.is_valid_ipv4("1.2.3")
    # valid IPv4
    assert Validator.is_valid_ipv4("192.168.1.1")
    assert Validator.is_valid_ipv4("0.0.0.0")
    assert Validator.is_valid_ipv4("255.255.255.255")


def test_parser_rejects_invalid_unicode_label():
    parser = Parser()
    bad_label = "\udcff"
    with pytest.raises(Exception):
        parser.parse(f"http://{bad_label}.com")

