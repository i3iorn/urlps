"""Tests for dangerous URL scheme blocking."""
import pytest
from urlps import parse_url, parse_url_unsafe, InvalidURLError
from urlps.constants import UNSAFE_SCHEMES


class TestDangerousSchemes:
    """Test dangerous scheme blocking."""

    def test_unsafe_schemes_defined(self):
        """Verify all expected unsafe schemes are defined."""
        expected_schemes = {
            "javascript", "data", "vbscript",  # Script execution
            "jar", "file",  # Local file access
            "gopher", "dict", "tftp",  # Protocol exploitation
            "ldap", "ldaps",  # Information disclosure
        }
        assert expected_schemes.issubset(UNSAFE_SCHEMES)

    def test_javascript_scheme_blocked(self):
        """javascript: scheme should be blocked."""
        with pytest.raises(InvalidURLError, match="custom_scheme"):
            parse_url("javascript:alert(1)")

    def test_data_scheme_blocked(self):
        """data: scheme should be blocked."""
        with pytest.raises(InvalidURLError, match="custom_scheme"):
            parse_url("data:text/html,<script>alert(1)</script>")

    def test_vbscript_scheme_blocked(self):
        """vbscript: scheme should be blocked."""
        with pytest.raises(InvalidURLError, match="custom_scheme"):
            parse_url("vbscript:msgbox(1)")

    def test_jar_scheme_blocked(self):
        """jar: scheme should be blocked (Java JAR file access)."""
        with pytest.raises(InvalidURLError, match="custom_scheme"):
            parse_url("jar://example.com/app.jar")

    def test_file_scheme_blocked(self):
        """file: scheme should be blocked (filesystem access)."""
        with pytest.raises(InvalidURLError, match="custom_scheme"):
            parse_url("file:///etc/passwd")

    def test_gopher_scheme_blocked(self):
        """gopher: scheme should be blocked (arbitrary TCP payloads)."""
        with pytest.raises(InvalidURLError, match="custom_scheme"):
            parse_url("gopher://localhost:11211/_stats%0aquit")

    def test_dict_scheme_blocked(self):
        """dict: scheme should be blocked (DICT protocol)."""
        with pytest.raises(InvalidURLError, match="custom_scheme"):
            parse_url("dict://localhost:11211/stat")

    def test_tftp_scheme_blocked(self):
        """tftp: scheme should be blocked."""
        with pytest.raises(InvalidURLError, match="custom_scheme"):
            parse_url("tftp://192.168.1.1/config.txt")

    def test_ldap_scheme_blocked(self):
        """ldap: scheme should be blocked."""
        with pytest.raises(InvalidURLError, match="custom_scheme"):
            parse_url("ldap://localhost/dc=example,dc=com")

    def test_ldaps_scheme_blocked(self):
        """ldaps: scheme should be blocked."""
        with pytest.raises(InvalidURLError, match="custom_scheme"):
            parse_url("ldaps://localhost/dc=example,dc=com")

    def test_safe_schemes_allowed(self):
        """Safe schemes should be allowed."""
        url1 = parse_url("http://example.com/")
        assert url1.scheme == "http"

        url2 = parse_url("https://example.com/")
        assert url2.scheme == "https"

        url3 = parse_url("ftp://ftp.example.com/")
        assert url3.scheme == "ftp"

    def test_dangerous_schemes_allowed_with_custom_flag(self):
        """Dangerous schemes should be allowed with allow_custom_scheme=True."""
        url1 = parse_url_unsafe("javascript:alert(1)", allow_custom_scheme=True)
        assert url1.scheme == "javascript"

        url2 = parse_url_unsafe("file:///etc/passwd", allow_custom_scheme=True)
        assert url2.scheme == "file"

        url3 = parse_url_unsafe("gopher://localhost/", allow_custom_scheme=True)
        assert url3.scheme == "gopher"


class TestRealWorldAttackScenarios:
    """Test real-world attack scenarios with dangerous schemes."""

    def test_ssrf_via_gopher(self):
        """SSRF attack via gopher protocol should be blocked."""
        # Gopher can send arbitrary TCP payloads to internal services
        with pytest.raises(InvalidURLError):
            parse_url("gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a")

    def test_file_access_attack(self):
        """Local file access attacks should be blocked."""
        with pytest.raises(InvalidURLError):
            parse_url("file:///etc/passwd")

        with pytest.raises(InvalidURLError):
            parse_url("file:///c:/windows/system32/config/sam")

    def test_jar_file_access(self):
        """JAR protocol file access should be blocked."""
        with pytest.raises(InvalidURLError):
            parse_url("jar://example.com/malicious.jar")

    def test_ldap_injection(self):
        """LDAP injection attempts should be blocked."""
        with pytest.raises(InvalidURLError):
            parse_url("ldap://localhost/dc=example,dc=com?mail?sub?(objectClass=*)")

    def test_data_uri_xss(self):
        """Data URI XSS attempts should be blocked."""
        with pytest.raises(InvalidURLError):
            parse_url("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==")

    def test_javascript_xss(self):
        """JavaScript XSS attempts should be blocked."""
        with pytest.raises(InvalidURLError):
            parse_url("javascript:void(document.cookie='stolen')")

    def test_dict_protocol_exploit(self):
        """DICT protocol exploitation should be blocked."""
        with pytest.raises(InvalidURLError):
            parse_url("dict://attacker.com:11211/stat")


class TestSchemeCaseSensitivity:
    """Test that scheme detection is case-insensitive."""

    def test_uppercase_dangerous_schemes_blocked(self):
        """Uppercase dangerous schemes should also be blocked."""
        with pytest.raises(InvalidURLError):
            parse_url("JAVASCRIPT:alert(1)")

        with pytest.raises(InvalidURLError):
            parse_url("FILE:///etc/passwd")

        with pytest.raises(InvalidURLError):
            parse_url("GOPHER://localhost/")

    def test_mixed_case_dangerous_schemes_blocked(self):
        """Mixed case dangerous schemes should also be blocked."""
        with pytest.raises(InvalidURLError):
            parse_url("JavaScript:alert(1)")

        with pytest.raises(InvalidURLError):
            parse_url("FiLe:///etc/passwd")

        with pytest.raises(InvalidURLError):
            parse_url("GoPhEr://localhost/")
