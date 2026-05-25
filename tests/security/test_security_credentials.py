"""Tests for credential leakage detection."""
import pytest
from urlps._security import has_credentials


class TestCredentialDetection:
    """Test basic credential detection in URLs."""

    def test_url_with_username_and_password(self):
        """URLs with username and password should be detected."""
        assert has_credentials("http://user:pass@example.com")
        assert has_credentials("https://admin:secret123@api.example.com/v1")
        assert has_credentials("ftp://john:doe@ftp.example.com")

    def test_url_with_username_only(self):
        """URLs with username only (no password) should be detected."""
        assert has_credentials("http://user@example.com")
        assert has_credentials("https://admin@api.example.com")
        assert has_credentials("ssh://git@github.com/repo.git")

    def test_url_without_credentials(self):
        """URLs without credentials should return False."""
        assert not has_credentials("http://example.com")
        assert not has_credentials("https://api.example.com/v1")
        assert not has_credentials("ftp://ftp.example.com")

    def test_url_with_port(self):
        """URLs with port numbers should be correctly handled."""
        assert has_credentials("http://user:pass@example.com:8080")
        assert has_credentials("https://admin@example.com:443/path")
        assert not has_credentials("http://example.com:8080")

    def test_url_with_path(self):
        """URLs with paths should be correctly handled."""
        assert has_credentials("http://user:pass@example.com/path/to/resource")
        assert has_credentials("https://admin@api.example.com/v1/users")
        assert not has_credentials("http://example.com/path/with/@/char")

    def test_url_with_query_string(self):
        """URLs with query strings should be correctly handled."""
        assert has_credentials("http://user:pass@example.com?key=value")
        assert has_credentials("https://admin@api.example.com/path?token=abc")
        assert not has_credentials("http://example.com?email=user@example.com")

    def test_url_with_fragment(self):
        """URLs with fragments should be correctly handled."""
        assert has_credentials("http://user:pass@example.com#section")
        assert has_credentials("https://admin@api.example.com/path#anchor")
        assert not has_credentials("http://example.com#section@anchor")


class TestCredentialEdgeCases:
    """Test edge cases for credential detection."""

    def test_multiple_at_signs(self):
        """Multiple @ signs should still detect credentials (first one counts)."""
        # First @ indicates userinfo, second @ might be in password
        assert has_credentials("http://user:p@ss@example.com")
        assert has_credentials("http://user@name:pass@example.com")

    def test_empty_credentials(self):
        """Empty username or password should still be detected."""
        assert has_credentials("http://:password@example.com")
        assert has_credentials("http://username:@example.com")
        assert has_credentials("http://@example.com")  # Edge case: just @

    def test_url_without_scheme(self):
        """URLs without scheme should return False."""
        assert not has_credentials("example.com")
        assert not has_credentials("user:pass@example.com")  # No scheme
        assert not has_credentials("//user:pass@example.com")  # Scheme-relative

    def test_special_characters_in_credentials(self):
        """Special characters in credentials should be detected."""
        assert has_credentials("http://user%40:pass%21@example.com")
        assert has_credentials("https://user+name:p@ssw0rd@example.com")
        assert has_credentials("ftp://admin!:secret$@ftp.example.com")

    def test_ipv4_address_with_credentials(self):
        """IPv4 addresses with credentials should be detected."""
        assert has_credentials("http://user:pass@192.168.1.1")
        assert has_credentials("https://admin@10.0.0.1:8080")

    def test_ipv6_address_with_credentials(self):
        """IPv6 addresses with credentials should be detected."""
        assert has_credentials("http://user:pass@[::1]")
        assert has_credentials("https://admin@[2001:db8::1]:8080")
        assert has_credentials("http://user@[fe80::1%25eth0]")

    def test_localhost_with_credentials(self):
        """Localhost URLs with credentials should be detected."""
        assert has_credentials("http://user:pass@localhost")
        assert has_credentials("https://admin@localhost:8080")

    def test_invalid_input_types(self):
        """Non-string inputs should return False."""
        assert not has_credentials(None)
        assert not has_credentials(123)
        assert not has_credentials([])
        assert not has_credentials({})


class TestCredentialSecurityScenarios:
    """Test real-world security scenarios involving credentials."""

    def test_database_urls_with_credentials(self):
        """Database connection URLs often contain credentials."""
        assert has_credentials("postgresql://user:password@localhost:5432/dbname")
        assert has_credentials("mysql://root:secret@127.0.0.1:3306/mydb")
        assert has_credentials("mongodb://admin:pass123@mongo.example.com/db")

    def test_ftp_with_credentials(self):
        """FTP URLs commonly use credentials."""
        assert has_credentials("ftp://anonymous:guest@ftp.example.com")
        assert has_credentials("ftps://user:pass@secure.example.com/files")

    def test_http_basic_auth_pattern(self):
        """HTTP Basic Auth uses credentials in URL."""
        assert has_credentials("http://user:pass@api.example.com/endpoint")
        assert has_credentials("https://apikey:x@api.service.com/v1/data")

    def test_git_urls_with_credentials(self):
        """Git URLs may contain credentials."""
        assert has_credentials("https://token:x-oauth-basic@github.com/user/repo.git")
        assert has_credentials("https://oauth2:ACCESS_TOKEN@gitlab.com/project.git")

    def test_smtp_with_credentials(self):
        """SMTP URLs may contain credentials."""
        assert has_credentials("smtp://user:pass@mail.example.com:587")
        assert has_credentials("smtps://admin:secret@smtp.gmail.com:465")

    def test_redis_with_credentials(self):
        """Redis URLs may contain credentials."""
        assert has_credentials("redis://user:password@localhost:6379/0")
        assert has_credentials("rediss://default:secret@redis.example.com:6380")

    def test_safe_urls_without_credentials(self):
        """Common safe URLs should not trigger false positives."""
        assert not has_credentials("https://www.example.com/page")
        assert not has_credentials("http://api.example.com/v1/users")
        assert not has_credentials("ws://localhost:8080/socket")
        assert not has_credentials("file:///path/to/file")


class TestCredentialInPathOrQuery:
    """Test that @ signs in path or query don't trigger false positives."""

    def test_at_sign_in_query_parameter(self):
        """@ sign in query parameter should not trigger detection."""
        assert not has_credentials("http://example.com?email=user@domain.com")
        assert not has_credentials("https://api.example.com/search?q=test@example")

    def test_at_sign_in_path(self):
        """@ sign in path should not trigger detection."""
        assert not has_credentials("http://example.com/user@123/profile")
        assert not has_credentials("https://example.com/@username")

    def test_at_sign_in_fragment(self):
        """@ sign in fragment should not trigger detection."""
        assert not has_credentials("http://example.com/page#user@anchor")
        assert not has_credentials("https://example.com#@section")

    def test_credentials_vs_path_at_sign(self):
        """Ensure we correctly distinguish credentials from path @ signs."""
        # Has credentials
        assert has_credentials("http://user@example.com/path")
        # No credentials, @ is in path
        assert not has_credentials("http://example.com/user@domain")
        # Has credentials even with @ in path
        assert has_credentials("http://user@example.com/path/@user")


class TestCredentialWarnings:
    """Test scenarios where credential detection is important for warnings."""

    def test_http_with_credentials_insecure(self):
        """HTTP (not HTTPS) with credentials is especially dangerous."""
        assert has_credentials("http://user:pass@example.com")
        # This should trigger a warning in production code
        # as credentials are transmitted in plaintext

    def test_credentials_in_referrer(self):
        """Credentials in URLs may leak via Referrer header."""
        url = "https://user:pass@api.example.com/endpoint"
        assert has_credentials(url)
        # In production, this should warn about potential referrer leakage

    def test_credentials_in_logs(self):
        """Credentials in URLs may be logged."""
        assert has_credentials("https://admin:secret@internal.company.com/api")
        # Production systems should sanitize logs to remove credentials

    def test_empty_password_still_credential_leak(self):
        """Even empty passwords are credential leaks."""
        assert has_credentials("http://username:@example.com")
        assert has_credentials("http://username@example.com")
        # Both indicate credential presence, even if password is empty
