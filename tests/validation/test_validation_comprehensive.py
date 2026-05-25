"""
Additional comprehensive validation tests for urlp.
Tests edge cases, security considerations, and boundary conditions.
"""
import pytest
from urlps._validation import Validator
from urlps._security import is_private_ip
from urlps import parse_url, parse_url_unsafe
from urlps.exceptions import InvalidURLError, URLParseError


class TestSchemeValidationComprehensive:
    """Comprehensive scheme validation tests."""

    def test_valid_schemes(self):
        """Test various valid scheme formats"""
        valid_schemes = [
            "http", "https", "ftp", "ftps", "ssh", "file",
            "a", "z",  # single char
            "http+ssh",  # with plus
            "my-scheme",  # with hyphen
            "my.scheme",  # with dot
            "a0", "scheme2", "http2",  # with numbers
        ]
        for scheme in valid_schemes:
            assert Validator.is_valid_scheme(scheme), f"Failed for {scheme}"

    def test_invalid_schemes(self):
        """Test invalid scheme formats"""
        invalid_schemes = [
            "",  # empty
            "0http",  # starts with digit
            "-http",  # starts with hyphen
            ".http",  # starts with dot
            "+http",  # starts with plus
            "http_ssh",  # underscore not allowed
            "http ssh",  # space not allowed
            "http!",  # exclamation not allowed
            "a" * 17,  # too long (>16 chars)
            "HTTP",  # uppercase (scheme should be lowercase)
            123,  # not a string
            None,  # not a string
        ]
        for scheme in invalid_schemes:
            assert not Validator.is_valid_scheme(scheme), f"Should fail for {scheme}"


class TestHostValidationComprehensive:
    """Comprehensive host validation tests."""

    def test_valid_hostnames(self):
        """Test valid hostname formats"""
        valid_hosts = [
            "example.com",
            "sub.example.com",
            "sub.sub.example.com",
            "a.b.c.d.e.f.com",
            "example-domain.com",
            "123.com",
            "example123.com",
            "ex123ample.com",
            "x.co",
            "a.b",
            "localhost",
            "my-server",
            "a" * 63 + ".com",  # Max label length
        ]
        for host in valid_hosts:
            assert Validator.is_valid_host(host), f"Failed for {host}"

    def test_invalid_hostnames(self):
        """Test invalid hostname formats"""
        invalid_hosts = [
            "",  # empty
            ".com",  # starts with dot
            "example..com",  # double dot
            "example-.com",  # label ends with hyphen
            "-example.com",  # label starts with hyphen
            "example.com-",  # label ends with hyphen
            "exam ple.com",  # space
            "example_.com",  # underscore
            "example!.com",  # exclamation
            "a" * 64 + ".com",  # Label too long
            123,  # not a string
            None,  # not a string
        ]
        for host in invalid_hosts:
            assert not Validator.is_valid_host(host), f"Should fail for {host}"

    def test_punycode_domains(self):
        """Test punycode/IDN domains"""
        assert Validator.is_valid_host("xn--d1acpjx3f.xn--p1ai")  # россия.рф
        assert Validator.is_valid_host("xn--mller-kva.com")  # müller.com


class TestIPv4ValidationComprehensive:
    """Comprehensive IPv4 validation tests."""

    def test_valid_ipv4(self):
        """Test valid IPv4 addresses"""
        valid_ips = [
            "0.0.0.0",
            "127.0.0.1",
            "192.168.1.1",
            "255.255.255.255",
            "10.0.0.0",
            "172.16.0.0",
            "8.8.8.8",
            "1.2.3.4",
        ]
        for ip in valid_ips:
            assert Validator.is_valid_ipv4(ip), f"Failed for {ip}"

    def test_invalid_ipv4(self):
        """Test invalid IPv4 addresses"""
        invalid_ips = [
            "256.1.1.1",  # octet > 255
            "1.256.1.1",
            "1.1.256.1",
            "1.1.1.256",
            "1.1.1",  # too few octets
            "1.1.1.1.1",  # too many octets
            "1.1.1.a",  # non-numeric
            "1.1.1.-1",  # negative
            "",  # empty
            "....",  # just dots
            123,  # not a string
            None,  # not a string
        ]
        for ip in invalid_ips:
            assert not Validator.is_valid_ipv4(ip), f"Should fail for {ip}"


class TestIPv6ValidationComprehensive:
    """Comprehensive IPv6 validation tests."""

    def test_valid_ipv6(self):
        """Test valid IPv6 addresses"""
        valid_ips = [
            "[::1]",  # loopback
            "[2001:db8::1]",  # compressed
            "[2001:0db8:0000:0000:0000:0000:0000:0001]",  # full
            "[fe80::1]",  # link-local
            "[::ffff:192.0.2.1]",  # IPv4-mapped
            "[2001:db8::8a2e:370:7334]",
            "[::1234:5678]",
            "[2001:db8::]",
            "[::2001:db8:0:0:1]",
        ]
        for ip in valid_ips:
            assert Validator.is_valid_ipv6(ip), f"Failed for {ip}"

    def test_invalid_ipv6(self):
        """Test invalid IPv6 addresses"""
        invalid_ips = [
            "::1",  # missing brackets
            "[::1",  # missing closing bracket
            "::1]",  # missing opening bracket
            "[::g]",  # invalid hex
            "[:::1]",  # too many colons
            "",  # empty
            123,  # not a string
            None,  # not a string
        ]
        for ip in invalid_ips:
            assert not Validator.is_valid_ipv6(ip), f"Should fail for {ip}"

    def test_ipv6_with_zone_id(self):
        """Test IPv6 addresses with zone identifiers"""
        # Zone IDs are percent-encoded in URLs
        assert Validator.is_valid_ipv6("[fe80::1%25eth0]")
        assert Validator.is_valid_ipv6("[fe80::1%25en0]")


class TestPortValidationComprehensive:
    """Comprehensive port validation tests."""

    def test_valid_ports(self):
        """Test valid port numbers"""
        valid_ports = [
            1, 80, 443, 8080, 3000, 65535,
            "1", "80", "443", "65535",
        ]
        for port in valid_ports:
            assert Validator.is_valid_port(port), f"Failed for {port}"

    def test_invalid_ports(self):
        """Test invalid port numbers"""
        invalid_ports = [
            0,  # port 0 is invalid
            -1,  # negative
            65536,  # too large
            70000,  # too large
            "0",  # zero
            "-1",  # negative string
            "65536",  # too large string
            "abc",  # non-numeric
            "",  # empty
            None,  # None
            "80.0",  # float-like string
        ]
        for port in invalid_ports:
            assert not Validator.is_valid_port(port), f"Should fail for {port}"

    def test_standard_ports(self):
        """Test standard port recognition"""
        assert Validator.is_standard_port(80)
        assert Validator.is_standard_port(443)
        assert Validator.is_standard_port(21)
        assert Validator.is_standard_port(22)
        assert not Validator.is_standard_port(8080)
        assert not Validator.is_standard_port(3000)


class TestFragmentValidationComprehensive:
    """Comprehensive fragment validation tests."""

    def test_valid_fragments(self):
        """Test valid fragment formats"""
        valid_fragments = [
            "section1",
            "section-1",
            "section_1",  # underscores in fragment are okay
            "section.1",
            "section~1",
            "!$&'()*+,;=",  # sub-delims
            ":@",  # gen-delims allowed in fragment
            "/?",  # path and query chars
            "a" * 1000,  # long fragment
            "",  # empty fragment
        ]
        for fragment in valid_fragments:
            assert Validator.is_valid_fragment(fragment), f"Failed for {fragment}"

    def test_invalid_fragments(self):
        """Test invalid fragment formats"""
        invalid_fragments = [
            "section 1",  # space
            "section%1",  # incomplete percent-encoding
            "section%GG",  # invalid percent-encoding
            "section\n",  # newline
            "section\t",  # tab
            123,  # not a string
            None,  # not a string
        ]
        for fragment in invalid_fragments:
            assert not Validator.is_valid_fragment(fragment), f"Should fail for {fragment}"


class TestIPAddressDetection:
    """Test IP address detection."""

    def test_is_ip_address(self):
        """Test IP address detection"""
        assert Validator.is_ip_address("192.168.1.1")
        assert Validator.is_ip_address("[::1]")
        assert Validator.is_ip_address("[2001:db8::1]")
        assert not Validator.is_ip_address("example.com")
        assert not Validator.is_ip_address("localhost")
        assert not Validator.is_ip_address("")

    def test_is_private_ip(self):
        """Test private IP detection"""
        # IPv4 private ranges
        assert is_private_ip("10.0.0.1")
        assert is_private_ip("172.16.0.1")
        assert is_private_ip("192.168.1.1")
        assert is_private_ip("127.0.0.1")  # loopback

        # IPv6 private
        assert is_private_ip("[::1]")  # loopback
        assert is_private_ip("[fe80::1]")  # link-local
        assert is_private_ip("[fc00::1]")  # unique local

        # Public IPs
        assert not is_private_ip("8.8.8.8")
        assert not is_private_ip("1.1.1.1")
        assert not is_private_ip("[2001:4860:4860::8888]")

        # Not IP addresses
        assert not is_private_ip("example.com")
        assert not is_private_ip("")


class TestSecurityConsiderations:
    """Test security-related validations."""

    def test_null_byte_rejection(self):
        """Null bytes should be rejected"""
        with pytest.raises(InvalidURLError):
            parse_url("http://example.com/path\x00injection")

    def test_control_character_rejection(self):
        """Control characters should be rejected"""
        control_chars = ["\x01", "\x02", "\x1F", "\x7F"]
        for char in control_chars:
            with pytest.raises(InvalidURLError):
                parse_url(f"http://example.com/path{char}test")

    def test_javascript_protocol_requires_custom_scheme(self):
        """javascript: protocol should require custom_scheme flag"""
        with pytest.raises(InvalidURLError):
            parse_url("javascript:alert(1)")

    def test_data_protocol_requires_custom_scheme(self):
        """data: protocol should require custom_scheme flag"""
        with pytest.raises(InvalidURLError):
            parse_url("data:text/html,<h1>Hello</h1>")

    def test_file_protocol_localhost(self):
        """File URLs should work with localhost"""
        url = parse_url("file:///etc/passwd", allow_custom_scheme=True)
        assert url.scheme == "file"
        assert url.path == "/etc/passwd"

    def test_extremely_long_components(self):
        """Test handling of extremely long components"""
        # Path within security limit (MAX_PATH_LENGTH = 4096) should work
        acceptable_path = "/a" * 2000
        url = parse_url(f"http://example.com{acceptable_path}")
        assert url.path == acceptable_path

        # Very long path exceeding security limit should be rejected
        long_path = "/a" * 10000
        with pytest.raises((URLParseError, InvalidURLError)):
            parse_url(f"http://example.com{long_path}")

        # Very long host should fail if exceeds DNS limits
        long_label = "a" * 64
        with pytest.raises(InvalidURLError):
            parse_url(f"http://{long_label}.com/")

    def test_unicode_security(self):
        """Test unicode homograph attack prevention via IDNA"""
        # parse_url now blocks mixed scripts by default
        # Use parse_url_unsafe to test IDNA encoding still works
        url = parse_url_unsafe("http://раypal.com/")  # Cyrillic 'a'
        # Should be punycode encoded
        assert "xn--" in url.host

    def test_port_overflow(self):
        """Test port number overflow"""
        with pytest.raises(InvalidURLError):
            parse_url("http://example.com:99999/")

    def test_userinfo_injection(self):
        """Test userinfo injection attempts"""
        # Multiple @ signs should fail
        with pytest.raises(InvalidURLError):
            parse_url("http://user@evil.com@example.com/")


class TestBoundaryConditions:
    """Test boundary conditions and edge cases."""

    def test_empty_components(self):
        """Test empty components"""
        url = parse_url("http://example.com")
        assert url.query is None
        assert url.fragment is None
        assert url.userinfo is None

    def test_single_char_components(self):
        """Test single character components"""
        url = parse_url("http://a.b/c?d=e#f")
        assert url.host == "a.b"
        assert url.path == "/c"
        assert url.fragment == "f"

    def test_max_length_scheme(self):
        """Test maximum length scheme (16 chars)"""
        scheme = "a" * 16
        assert Validator.is_valid_scheme(scheme)

        too_long = "a" * 17
        assert not Validator.is_valid_scheme(too_long)

    def test_max_length_host_label(self):
        """Test maximum length host label (63 chars)"""
        max_label = "a" * 63
        assert Validator.is_valid_host(max_label + ".com")

        too_long_label = "a" * 64
        assert not Validator.is_valid_host(too_long_label + ".com")

    def test_max_port_number(self):
        """Test maximum port number (65535)"""
        url = parse_url("http://example.com:65535/")
        assert url.port == 65535

        with pytest.raises(InvalidURLError):
            parse_url("http://example.com:65536/")

    def test_min_port_number(self):
        """Test minimum port number (1)"""
        url = parse_url("http://example.com:1/")
        assert url.port == 1

        with pytest.raises(InvalidURLError):
            parse_url("http://example.com:0/")


class TestUnicodeHandling:
    """Test Unicode handling in various components."""

    def test_unicode_host_idna(self):
        """Unicode in host should be IDNA encoded"""
        url = parse_url("http://münchen.de/")
        assert "xn--" in url.host

    def test_unicode_in_path(self):
        """Unicode in path should be percent-encoded"""
        from urlps import compose_url
        result = compose_url({
            "scheme": "http",
            "host": "example.com",
            "path": "/тест"
        })
        assert "%" in result

    def test_emoji_in_components(self):
        """Emoji and other Unicode should be handled"""
        from urlps import compose_url
        result = compose_url({
            "scheme": "http",
            "host": "example.com",
            "path": "/😀"
        })
        assert "%" in result  # Should be percent-encoded


class TestCachingBehavior:
    """Test that caching optimizations work correctly."""

    def test_idna_cache_consistency(self):
        """Multiple calls with same host should use cache"""
        # Parse same host multiple times
        for _ in range(10):
            url = parse_url("http://münchen.de/")
            assert "xn--" in url.host

        # Should still work with different hosts
        url2 = parse_url("http://zürich.ch/")
        assert "xn--" in url2.host

    def test_validation_consistency(self):
        """Validation should be consistent across calls"""
        for _ in range(10):
            assert Validator.is_valid_scheme("http")
            assert Validator.is_valid_host("example.com")
            assert Validator.is_valid_port(80)
