import pytest
import socket
from unittest.mock import Mock, patch, MagicMock
from urllib.error import URLError, HTTPError

from src.urlps.url import URL
from src.urlps.exceptions import InvalidURLError
from src.urlps._security.phishing_db import (
    refresh_phishing_db, check_against_phishing_db,
    get_phishing_db_info, clear_phishing_db
)


@pytest.fixture(autouse=True)
def clear_phishing_cache():
    # Ensure PHISHING_SET is reset before each test
    clear_phishing_db()
    yield
    clear_phishing_db()


class TestPhishingDBBasicFunctionality:
    """Test basic phishing database functionality."""

    def test_check_against_phishing_db_detects_known_host(self):
        fake_text = "malicious.example.com\nphish.bad\n"
        mock_resp = MagicMock()
        mock_resp.__enter__().read.return_value = fake_text.encode('utf-8')
        mock_resp.__enter__().status = 200

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp) as mocked_get:
            assert check_against_phishing_db("phish.bad") is True
            mocked_get.assert_called_once()

    def test_check_against_phishing_db_returns_false_for_safe_host(self):
        fake_text = "malicious.example.com\nphish.bad\n"
        mock_resp = MagicMock()
        mock_resp.__enter__().read.return_value = fake_text.encode('utf-8')
        mock_resp.__enter__().status = 200

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            assert check_against_phishing_db("good.example.com") is False

    def test_url_raises_on_phishing_domain(self):
        fake_text = "evil.com\n"
        mock_resp = MagicMock()
        mock_resp.__enter__().read.return_value = fake_text.encode('utf-8')
        mock_resp.__enter__().status = 200

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            with pytest.raises(InvalidURLError):
                URL("http://evil.com/", check_phishing=True)

    def test_non_string_inputs_return_false(self):
        assert check_against_phishing_db(None) is False
        assert check_against_phishing_db(123) is False

    def test_case_insensitive_matching(self):
        """Host matching should be case-insensitive."""
        fake_text = "malicious.example.com\n"
        mock_resp = MagicMock()
        mock_resp.__enter__().read.return_value = fake_text.encode('utf-8')
        mock_resp.__enter__().status = 200

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            assert check_against_phishing_db("MALICIOUS.EXAMPLE.COM") is True
            assert check_against_phishing_db("Malicious.Example.Com") is True

    def test_trailing_dot_normalization(self):
        """Hosts with trailing dots should be normalized."""
        fake_text = "malicious.example.com\n"
        mock_resp = MagicMock()
        mock_resp.__enter__().read.return_value = fake_text.encode('utf-8')
        mock_resp.__enter__().status = 200

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            assert check_against_phishing_db("malicious.example.com.") is True


class TestPhishingDBNetworkFailures:
    """Test handling of various network failures during phishing DB download."""

    def test_handles_generic_network_error(self):
        """OSError should result in empty set (safe fallback)."""
        refresh_phishing_db()
        with patch("src.urlps._security.phishing_db.request.urlopen", side_effect=OSError("network")) as mocked_get:
            assert check_against_phishing_db("phish.bad") is False
            mocked_get.assert_not_called()

    def test_handles_url_error(self):
        """URLError (e.g., DNS failure) should result in empty set."""
        with patch("src.urlps._security.phishing_db.request.urlopen", side_effect=URLError("DNS lookup failed")):
            assert check_against_phishing_db("any.host") is False

    def test_handles_http_404_error(self):
        """HTTP 404 error should result in empty set."""
        error = HTTPError(
            url="https://phish.co.za/latest/ALL-phishing-domains.lst",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None
        )
        with patch("src.urlps._security.phishing_db.request.urlopen", side_effect=error):
            assert check_against_phishing_db("any.host") is False

    def test_handles_http_500_error(self):
        """HTTP 500 error should result in empty set."""
        error = HTTPError(
            url="https://phish.co.za/latest/ALL-phishing-domains.lst",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=None
        )
        with patch("src.urlps._security.phishing_db.request.urlopen", side_effect=error):
            assert check_against_phishing_db("any.host") is False

    def test_handles_connection_timeout(self):
        """Connection timeout should result in empty set."""
        with patch("src.urlps._security.phishing_db.request.urlopen", side_effect=socket.timeout("timed out")):
            assert check_against_phishing_db("any.host") is False

    def test_handles_connection_refused(self):
        """Connection refused should result in empty set."""
        with patch("src.urlps._security.phishing_db.request.urlopen", side_effect=ConnectionRefusedError()):
            assert check_against_phishing_db("any.host") is False

    def test_handles_ssl_error(self):
        """SSL errors should result in empty set."""
        import ssl
        ssl_error = ssl.SSLError("certificate verify failed")
        with patch("src.urlps._security.phishing_db.request.urlopen", side_effect=ssl_error):
            assert check_against_phishing_db("any.host") is False


class TestPhishingDBResponseHandling:
    """Test handling of various response scenarios."""

    def test_handles_non_200_status(self):
        """Non-200 status codes should result in empty set."""
        mock_resp = MagicMock()
        mock_resp.__enter__().read.return_value = b"Service Unavailable"
        mock_resp.__enter__().status = 503

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            assert check_against_phishing_db("any.host") is False

    def test_handles_empty_response(self):
        """Empty response should result in empty set."""
        mock_resp = MagicMock()
        mock_resp.__enter__().status = 200
        mock_resp.__enter__().read.return_value = b""

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            assert check_against_phishing_db("any.host") is False

    def test_handles_malformed_utf8(self):
        """Malformed UTF-8 should be handled gracefully."""
        mock_resp = MagicMock()
        mock_resp.__enter__().status = 200
        # Invalid UTF-8 bytes
        mock_resp.__enter__().read.return_value = b"valid.host\n\xff\xfe\ninvalid\xc0\xc1.host\n"

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            # Should still work with valid entries, ignoring invalid bytes
            result = check_against_phishing_db("valid.host")
            assert result is True

    def test_handles_whitespace_and_empty_lines(self):
        """Empty lines and whitespace should be handled."""
        mock_resp = MagicMock()
        mock_resp.__enter__().status = 200
        mock_resp.__enter__().read.return_value = b"\n\n  \nphish.bad\n  \n\nother.bad\n\n"

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            assert check_against_phishing_db("phish.bad") is True
            assert check_against_phishing_db("other.bad") is True
            assert check_against_phishing_db("") is False

    def test_handles_very_large_response(self):
        """Large response should be processed correctly."""
        # Generate a large list of hosts
        hosts = [f"host{i}.example.com" for i in range(10000)]
        fake_text = "\n".join(hosts)

        mock_resp = MagicMock()
        mock_resp.__enter__().status = 200
        mock_resp.__enter__().read.return_value = fake_text.encode('utf-8')

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            assert check_against_phishing_db("host0.example.com") is True
            assert check_against_phishing_db("host9999.example.com") is True
            assert check_against_phishing_db("notinlist.example.com") is False


class TestDownloadPhishingDBDirectly:
    """Test _download_phishing_db function directly."""

    def test_returns_set_on_success(self):
        """Should return a set of hostnames on success."""
        mock_resp = MagicMock()
        mock_resp.__enter__().status = 200
        mock_resp.__enter__().read.return_value = b"host1.com\nhost2.com\n"

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            result = refresh_phishing_db()
            assert result == 2
            assert check_against_phishing_db("host1.com")
            assert check_against_phishing_db("host2.com")


class TestPhishingDBRefresh:
    """Test phishing database refresh functionality."""

    def test_refresh_phishing_db_redownloads(self):
        """refresh_phishing_db should re-download the database."""
        # First, set up initial database
        mock_resp1 = MagicMock()()
        mock_resp1.__enter__().status = 200
        mock_resp1.__enter__().read.return_value = b"old.domain.com\n"

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp1):
            check_against_phishing_db("old.domain.com")
            assert check_against_phishing_db("old.domain.com") is True
            assert check_against_phishing_db("new.domain.com") is False

        # Now refresh with new data
        mock_resp2 = MagicMock()()
        mock_resp2.__enter__().status = 200
        mock_resp2.__enter__().read.return_value = b"new.domain.com\n"

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp2):
            count = refresh_phishing_db()
            assert count == 1
            assert check_against_phishing_db("new.domain.com") is True
            assert check_against_phishing_db("old.domain.com") is False

    def test_refresh_phishing_db_returns_count(self):
        """refresh_phishing_db should return the number of hostnames."""
        mock_resp = MagicMock()
        mock_resp.__enter__().status = 200
        mock_resp.__enter__().read.return_value = b"host1.com\nhost2.com\nhost3.com\n"

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            count = refresh_phishing_db()
            assert count == 3

    def test_get_phishing_db_info_before_load(self):
        """get_phishing_db_info should show not loaded before first use."""
        info = get_phishing_db_info()
        assert info["loaded"] is False
        assert info["size"] == 0

    def test_get_phishing_db_info_after_load(self):
        """get_phishing_db_info should show loaded after first use."""
        mock_resp = MagicMock()
        mock_resp.__enter__().status = 200
        mock_resp.__enter__().read.return_value = b"host1.com\nhost2.com\n"

        with patch("src.urlps._security.phishing_db.request.urlopen", return_value=mock_resp):
            check_against_phishing_db("any.host")

        info = get_phishing_db_info()
        assert info["loaded"] is True
        assert info["size"] == 2

    def test_refresh_handles_failure_gracefully(self):
        """refresh_phishing_db should handle failures gracefully."""
        with patch("src.urlps._security.phishing_db.request.urlopen", side_effect=OSError("fail")):
            count = refresh_phishing_db()
            assert count == 0

        info = get_phishing_db_info()
        assert info["loaded"] is False
        assert info["size"] == 0
