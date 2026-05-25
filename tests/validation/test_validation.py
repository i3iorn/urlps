from urlps._validation import Validator


def test_is_valid_scheme_basic():
    assert Validator.is_valid_scheme("http")
    assert Validator.is_valid_scheme("a")  # single-character scheme allowed
    assert Validator.is_valid_scheme("foo+bar")
    assert not Validator.is_valid_scheme("1http")
    assert not Validator.is_valid_scheme(123)  # type: ignore[arg-type]


def test_is_valid_host_and_unicode():
    assert Validator.is_valid_host("example.com")
    assert Validator.is_valid_host("localhost")
    assert Validator.is_valid_host("xn--d1acpjx3f.xn--p1ai")  # punycode
    # unusual unicode label is not valid pre-idna; Validator expects ASCII/LDH
    assert not Validator.is_valid_host("\udcff")


def test_is_valid_ipv6_cases():
    assert Validator.is_valid_ipv6("[2001:db8::1]")
    assert not Validator.is_valid_ipv6("2001:db8::1")
    assert not Validator.is_valid_ipv6(123)  # type: ignore[arg-type]


def test_is_valid_fragment_and_edge_cases():
    assert Validator.is_valid_fragment("frag!$&'()*+,;=:@/?")
    assert not Validator.is_valid_fragment("bad%fragment")
    # non-string
    assert not Validator.is_valid_fragment(123)  # type: ignore[arg-type]


def test_extremely_long_components():
    long_scheme = "a" * 16  # allowed up to 16 chars
    assert Validator.is_valid_scheme(long_scheme)
    too_long_scheme = "a" * 17
    assert not Validator.is_valid_scheme(too_long_scheme)

    long_host_label = "a" * 63 + ".com"
    assert Validator.is_valid_host(long_host_label)
    too_long_host = ("a" * 64) + ".com"
    assert not Validator.is_valid_host(too_long_host)


def test_is_valid_port_edge_cases():
    assert Validator.is_valid_port(80)
    assert Validator.is_valid_port("443")
    assert not Validator.is_valid_port(70000)
    assert not Validator.is_valid_port("notanint")

