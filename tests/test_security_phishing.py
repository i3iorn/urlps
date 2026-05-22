import pytest
import socket
from unittest.mock import Mock, patch
from urllib.error import URLError, HTTPError

from src.urlps import _security
from src.urlps.url import URL
from src.urlps.exceptions import InvalidURLError


@pytest.fixture(autouse=True)
def clear_phishing_cache():
    # Ensure PHISHING_SET is reset before each test
    _security.PHISHING_SET = None
    yield
    _security.PHISHING_SET = None


class TestPhishingDBBasicFunctionality:
    """Test basic phishing database functionality."""

    def test_check_against_phishing_db_detects_known_host(self):
        fake_text = "malicious.example.com\nphish.bad\n"
        mock_resp = Mock()
        mock_resp.read.return_value = fake_text.encode('utf-8')
        mock_resp.status = 200

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp) as mocked_get:
            assert _security.check_against_phishing_db("phish.bad") is True
            mocked_get.assert_called_once()

    def test_check_against_phishing_db_returns_false_for_safe_host(self):
        fake_text = "malicious.example.com\nphish.bad\n"
        mock_resp = Mock()
        mock_resp.read.return_value = fake_text.encode('utf-8')
        mock_resp.status = 200

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            assert _security.check_against_phishing_db("good.example.com") is False

    def test_caching_prevents_multiple_downloads(self):
        # Patch the internal downloader to return a proper set
        with patch("src.urlps._security._download_phishing_db", return_value={"one", "two"}) as mocked_get:
            # First call triggers download
            assert _security.check_against_phishing_db("one") is True
            # Second call should use the cached PHISHING_SET
            assert _security.check_against_phishing_db("two") is True
            mocked_get.assert_called_once()

    def test_url_raises_on_phishing_domain(self):
        fake_text = "evil.com\n"
        mock_resp = Mock()
        mock_resp.read.return_value = fake_text.encode('utf-8')
        mock_resp.status = 200

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            with pytest.raises(InvalidURLError):
                URL("http://evil.com/", check_phishing=True)

    def test_non_string_inputs_return_false(self):
        assert _security.check_against_phishing_db(None) is False
        assert _security.check_against_phishing_db(123) is False

    def test_case_insensitive_matching(self):
        """Host matching should be case-insensitive."""
        fake_text = "malicious.example.com\n"
        mock_resp = Mock()
        mock_resp.read.return_value = fake_text.encode('utf-8')
        mock_resp.status = 200

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            assert _security.check_against_phishing_db("MALICIOUS.EXAMPLE.COM") is True
            assert _security.check_against_phishing_db("Malicious.Example.Com") is True

    def test_trailing_dot_normalization(self):
        """Hosts with trailing dots should be normalized."""
        fake_text = "malicious.example.com\n"
        mock_resp = Mock()
        mock_resp.read.return_value = fake_text.encode('utf-8')
        mock_resp.status = 200

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            assert _security.check_against_phishing_db("malicious.example.com.") is True


class TestPhishingDBNetworkFailures:
    """Test handling of various network failures during phishing DB download."""

    def test_handles_generic_network_error(self):
        """OSError should result in empty set (safe fallback)."""
        with patch("src.urlps._security.request.urlopen", side_effect=OSError("network")) as mocked_get:
            assert _security.check_against_phishing_db("phish.bad") is False
            mocked_get.assert_called_once()

    def test_handles_url_error(self):
        """URLError (e.g., DNS failure) should result in empty set."""
        with patch("src.urlps._security.request.urlopen", side_effect=URLError("DNS lookup failed")):
            assert _security.check_against_phishing_db("any.host") is False

    def test_handles_http_404_error(self):
        """HTTP 404 error should result in empty set."""
        error = HTTPError(
            url="https://phish.co.za/latest/ALL-phishing-domains.lst",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None
        )
        with patch("src.urlps._security.request.urlopen", side_effect=error):
            assert _security.check_against_phishing_db("any.host") is False

    def test_handles_http_500_error(self):
        """HTTP 500 error should result in empty set."""
        error = HTTPError(
            url="https://phish.co.za/latest/ALL-phishing-domains.lst",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=None
        )
        with patch("src.urlps._security.request.urlopen", side_effect=error):
            assert _security.check_against_phishing_db("any.host") is False

    def test_handles_connection_timeout(self):
        """Connection timeout should result in empty set."""
        with patch("src.urlps._security.request.urlopen", side_effect=socket.timeout("timed out")):
            assert _security.check_against_phishing_db("any.host") is False

    def test_handles_connection_refused(self):
        """Connection refused should result in empty set."""
        with patch("src.urlps._security.request.urlopen", side_effect=ConnectionRefusedError()):
            assert _security.check_against_phishing_db("any.host") is False

    def test_handles_ssl_error(self):
        """SSL errors should result in empty set."""
        import ssl
        ssl_error = ssl.SSLError("certificate verify failed")
        with patch("src.urlps._security.request.urlopen", side_effect=ssl_error):
            assert _security.check_against_phishing_db("any.host") is False


class TestPhishingDBResponseHandling:
    """Test handling of various response scenarios."""

    def test_handles_non_200_status(self):
        """Non-200 status codes should result in empty set."""
        mock_resp = Mock()
        mock_resp.status = 503
        mock_resp.read.return_value = b"Service Unavailable"

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            assert _security.check_against_phishing_db("any.host") is False

    def test_handles_empty_response(self):
        """Empty response should result in empty set."""
        mock_resp = Mock()
        mock_resp.status = 200
        mock_resp.read.return_value = b""

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            assert _security.check_against_phishing_db("any.host") is False

    def test_handles_malformed_utf8(self):
        """Malformed UTF-8 should be handled gracefully."""
        mock_resp = Mock()
        mock_resp.status = 200
        # Invalid UTF-8 bytes
        mock_resp.read.return_value = b"valid.host\n\xff\xfe\ninvalid\xc0\xc1.host\n"

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            # Should still work with valid entries, ignoring invalid bytes
            result = _security.check_against_phishing_db("valid.host")
            assert result is True

    def test_handles_whitespace_and_empty_lines(self):
        """Empty lines and whitespace should be handled."""
        mock_resp = Mock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"\n\n  \nphish.bad\n  \n\nother.bad\n\n"

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            assert _security.check_against_phishing_db("phish.bad") is True
            assert _security.check_against_phishing_db("other.bad") is True
            assert _security.check_against_phishing_db("") is False

    def test_handles_very_large_response(self):
        """Large response should be processed correctly."""
        # Generate a large list of hosts
        hosts = [f"host{i}.example.com" for i in range(10000)]
        fake_text = "\n".join(hosts)

        mock_resp = Mock()
        mock_resp.status = 200
        mock_resp.read.return_value = fake_text.encode('utf-8')

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            assert _security.check_against_phishing_db("host0.example.com") is True
            assert _security.check_against_phishing_db("host9999.example.com") is True
            assert _security.check_against_phishing_db("notinlist.example.com") is False


class TestDownloadPhishingDBDirectly:
    """Test _download_phishing_db function directly."""

    def test_returns_set_on_success(self):
        """Should return a set of hostnames on success."""
        mock_resp = Mock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"host1.com\nhost2.com\n"

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            result = _security._download_phishing_db()
            assert isinstance(result, set)
            assert "host1.com" in result
            assert "host2.com" in result

    def test_returns_empty_set_on_failure(self):
        """Should return empty set on network failure."""
        with patch("src.urlps._security.request.urlopen", side_effect=OSError("fail")):
            result = _security._download_phishing_db()
            assert result == set()

    def test_returns_empty_set_on_non_200(self):
        """Should return empty set on non-200 status."""
        mock_resp = Mock()
        mock_resp.status = 404

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            result = _security._download_phishing_db()
            assert result == set()


class TestPhishingDBRefresh:
    """Test phishing database refresh functionality."""

    def test_refresh_phishing_db_redownloads(self):
        """refresh_phishing_db should re-download the database."""
        # First, set up initial database
        mock_resp1 = Mock()
        mock_resp1.status = 200
        mock_resp1.read.return_value = b"old.domain.com\n"

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp1):
            _security.check_against_phishing_db("old.domain.com")
            assert _security.check_against_phishing_db("old.domain.com") is True
            assert _security.check_against_phishing_db("new.domain.com") is False

        # Now refresh with new data
        mock_resp2 = Mock()
        mock_resp2.status = 200
        mock_resp2.read.return_value = b"new.domain.com\n"

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp2):
            count = _security.refresh_phishing_db()
            assert count == 1
            assert _security.check_against_phishing_db("new.domain.com") is True
            assert _security.check_against_phishing_db("old.domain.com") is False

    def test_refresh_phishing_db_returns_count(self):
        """refresh_phishing_db should return the number of hostnames."""
        mock_resp = Mock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"host1.com\nhost2.com\nhost3.com\n"

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            count = _security.refresh_phishing_db()
            assert count == 3

    def test_get_phishing_db_info_before_load(self):
        """get_phishing_db_info should show not loaded before first use."""
        info = _security.get_phishing_db_info()
        assert info["loaded"] is False
        assert info["size"] == 0

    def test_get_phishing_db_info_after_load(self):
        """get_phishing_db_info should show loaded after first use."""
        mock_resp = Mock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"host1.com\nhost2.com\n"

        with patch("src.urlps._security.request.urlopen", return_value=mock_resp):
            _security.check_against_phishing_db("any.host")

        info = _security.get_phishing_db_info()
        assert info["loaded"] is True
        assert info["size"] == 2

    def test_refresh_handles_failure_gracefully(self):
        """refresh_phishing_db should handle failures gracefully."""
        with patch("src.urlps._security.request.urlopen", side_effect=OSError("fail")):
            count = _security.refresh_phishing_db()
            assert count == 0

        info = _security.get_phishing_db_info()
        assert info["loaded"] is True  # Still marked as loaded (with empty set)
        assert info["size"] == 0
