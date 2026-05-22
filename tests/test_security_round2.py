"""Security improvements tests - Round 2.

Tests for:
- #1: Open redirect detection
- #2: URL canonicalization
- #4: DNS rebinding protection (behind check_dns flag)
- #5: Cache management
- #6: Double-encoding detection
- #7: Secure defaults (parse_url is secure by default)
- #8: Path traversal detection
- #9: Semantic URL comparison
- #10: Audit logging
"""
import pytest
from unittest.mock import Mock, patch

from src.urlps import (
    parse_url,
    parse_url_unsafe,
    InvalidURLError,
    URLParseError,
    set_audit_callback,
    get_audit_callback,
)
from src.urlps._audit import get_callback_failure_metrics, reset_callback_failure_metrics
from src.urlps.constants import PASSWORD_MASK
from src.urlps._security import (
    is_open_redirect_risk,
    check_dns_rebinding,
    has_double_encoding,
    has_mixed_scripts,
    has_path_traversal,
)
from src.urlps._validation import Validator


class TestOpenRedirectDetection:
    """Tests for open redirect detection (improvement #1 round 2)."""

    def test_backslash_detected(self):
        """Backslash in path should be detected as redirect risk."""
        assert is_open_redirect_risk("\\\\evil.com")
        assert is_open_redirect_risk("/path\\to\\file")

    def test_double_slash_start_detected(self):
        """Double slash at start should be detected."""
        assert is_open_redirect_risk("//evil.com/path")

    def test_triple_slash_detected(self):
        """Triple slash should be detected."""
        assert is_open_redirect_risk("///evil.com")

    def test_normal_path_safe(self):
        """Normal paths should not be flagged."""
        assert not is_open_redirect_risk("/normal/path")
        assert not is_open_redirect_risk("/path/to/resource")
        assert not is_open_redirect_risk("/")

    def test_parse_url_rejects_redirect_risk(self):
        """parse_url should reject open redirect patterns."""
        # Path with backslash
        with pytest.raises(InvalidURLError, match="open redirect"):
            parse_url("http://example.com/path\\to\\evil")


class TestURLCanonicalization:
    """Tests for URL canonicalization (improvement #2 round 2)."""

    def test_scheme_lowercase(self):
        """Scheme should be normalized to lowercase."""
        url = parse_url("HTTP://EXAMPLE.COM/path")
        canonical = url.canonicalize()
        assert canonical.scheme == "http"

    def test_host_lowercase(self):
        """Host should be normalized to lowercase."""
        url = parse_url("http://EXAMPLE.COM/path")
        canonical = url.canonicalize()
        assert canonical.host == "example.com"

    def test_default_port_removed(self):
        """Default port should be removed."""
        url = parse_url("http://example.com:80/path")
        canonical = url.canonicalize()
        assert canonical.port is None

    def test_non_default_port_kept(self):
        """Non-default port should be preserved."""
        url = parse_url("http://example.com:8080/path")
        canonical = url.canonicalize()
        assert canonical.port == 8080

    def test_query_params_sorted(self):
        """Query parameters should be sorted."""
        url = parse_url("http://example.com/path?z=1&a=2&m=3")
        canonical = url.canonicalize()
        assert canonical.query == "a=2&m=3&z=1"



class TestPasswordMasking:
    """Tests for password masking (improvement #3 round 2)."""

    def test_password_masked_in_as_string(self):
        """Password should be masked when requested."""
        url = parse_url("http://user:secret@example.com/path")
        masked = url.as_string(mask_password=True)
        assert "secret" not in masked
        assert PASSWORD_MASK in masked
        assert "user:" in masked

    def test_password_not_masked_by_default(self):
        """Password should not be masked by default."""
        url = parse_url("http://user:secret@example.com/path")
        normal = url.as_string()
        assert "secret" in normal

    def test_no_password_unchanged(self):
        """URL without password should be unchanged."""
        url = parse_url("http://user@example.com/path")
        masked = url.as_string(mask_password=True)
        assert "user@" in masked

    def test_no_userinfo_unchanged(self):
        """URL without userinfo should be unchanged."""
        url = parse_url("http://example.com/path")
        masked = url.as_string(mask_password=True)
        assert masked == "http://example.com/path"


class TestDNSRebindingProtection:
    """Tests for DNS rebinding protection (improvement #4 round 2)."""

    def test_ip_address_direct_check(self):
        """Direct IP addresses should be checked without DNS."""
        assert check_dns_rebinding("8.8.8.8")
        assert not check_dns_rebinding("127.0.0.1")
        assert not check_dns_rebinding("192.168.1.1")
        assert not check_dns_rebinding("10.0.0.1")

    def test_check_dns_flag_separate_from_strict(self):
        """check_dns should work independently of strict mode."""
        # parse_url is now always strict - use parse_url_unsafe for non-strict
        url = parse_url_unsafe("http://google.com/", strict=True)
        assert url.host == "google.com"

        # check_dns is a separate flag
        url2 = parse_url_unsafe("http://google.com/", check_dns=False)
        assert url2.host == "google.com"

    @patch('src.urlps._security.socket.getaddrinfo')
    def test_dns_resolves_to_private_blocked(self, mock_getaddrinfo):
        """DNS that resolves to private IP should be blocked with check_dns."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('127.0.0.1', 0))  # Returns loopback
        ]

        assert not check_dns_rebinding("evil.example.com")

    @patch('src.urlps._security.socket.getaddrinfo')
    def test_dns_resolves_to_public_allowed(self, mock_getaddrinfo):
        """DNS that resolves to public IP should be allowed."""
        mock_getaddrinfo.return_value = [
            (2, 1, 6, '', ('93.184.216.34', 0))  # example.com IP
        ]

        assert check_dns_rebinding("example.com", enforce_rate_limit=False)

    def test_dns_resolution_failure_treated_as_unsafe(self):
        """DNS resolution failure should be treated as unsafe."""
        assert not check_dns_rebinding("definitely-not-a-real-domain-12345.invalid")


class TestCacheManagement:
    """Tests for cache management (improvement #5 round 2)."""

    def test_get_cache_info(self):
        """Should return cache statistics."""
        # Trigger some cache entries
        Validator.is_valid_host("example.com")
        Validator.is_valid_scheme("http")

        info = Validator.get_cache_info()

        assert 'is_valid_host' in info
        assert 'is_valid_scheme' in info
        assert isinstance(info['is_valid_host'], dict)
        assert 'hits' in info['is_valid_host']
        assert 'misses' in info['is_valid_host']

    def test_clear_caches(self):
        """Should clear all caches and return previous sizes."""
        # Populate caches
        Validator.is_valid_host("example.com")
        Validator.is_valid_scheme("http")

        previous = Validator.clear_caches()

        assert isinstance(previous, dict)
        assert 'is_valid_host' in previous

        # Verify caches are cleared
        info = Validator.get_cache_info()
        assert info['is_valid_host']['currsize'] == 0


class TestDoubleEncodingDetection:
    """Tests for double-encoding detection (improvement #6 round 2)."""

    def test_double_encoded_slash(self):
        """Should detect double-encoded slash (%252F)."""
        assert has_double_encoding("%252F")  # %2F encoded

    def test_double_encoded_dot(self):
        """Should detect double-encoded dot (%252E)."""
        assert has_double_encoding("%252E")  # %2E encoded

    def test_single_encoding_safe(self):
        """Single encoding should not be flagged."""
        assert not has_double_encoding("%2F")
        assert not has_double_encoding("%2E")

    def test_no_encoding_safe(self):
        """Plain text should not be flagged."""
        assert not has_double_encoding("/path/to/file")
        assert not has_double_encoding("normal text")

    def test_parse_url_rejects_double_encoding(self):
        """parse_url should reject double-encoded URLs."""
        with pytest.raises(InvalidURLError, match="double-encoded"):
            parse_url("http://example.com/path%252Ftraversal")


class TestSecureDefaults:
    """Tests for secure defaults - parse_url is secure by default (improvement #7 round 2)."""

    def test_strict_mode_enabled_by_default(self):
        """Strict mode should be enabled."""
        with pytest.raises(InvalidURLError):
            parse_url("http://127.0.0.1/")

    def test_urls_are_immutable(self):
        """URLs are immutable and hashable."""
        url = parse_url("http://example.com/path")
        # URLs are always immutable - can be hashed
        assert hash(url) is not None

    def test_rejects_ssrf_risks(self):
        """Should reject SSRF risks."""
        with pytest.raises(InvalidURLError):
            parse_url("http://localhost/")

        with pytest.raises(InvalidURLError):
            parse_url("http://192.168.1.1/")

    def test_rejects_path_traversal(self):
        """Should reject path traversal."""
        with pytest.raises(InvalidURLError, match="path traversal"):
            parse_url("http://example.com/path/../../../etc/passwd")

    def test_rejects_mixed_scripts(self):
        """Should reject mixed scripts in host."""
        # Test the validator directly first
        cyrillic_a = '\u0430'  # Cyrillic small letter a
        mixed_host = f"ex{cyrillic_a}mple"
        assert has_mixed_scripts(mixed_host), "Validator should detect mixed scripts"

        # parse_url checks mixed scripts on original host before IDNA encoding
        with pytest.raises(InvalidURLError, match="mixed Unicode scripts"):
            parse_url(f"http://{mixed_host}.com/")

    def test_accepts_safe_urls(self):
        """Should accept safe URLs."""
        url = parse_url("http://example.com/path?query=value#fragment")
        assert url.host == "example.com"
        assert url.path == "/path"


class TestPathTraversalDetection:
    """Tests for path traversal detection (improvement #8 round 2)."""

    def test_dot_dot_detected(self):
        """Should detect .. in path."""
        assert has_path_traversal("../../../etc/passwd")
        assert has_path_traversal("/path/../secret")

    def test_encoded_dot_dot_detected(self):
        """Should detect encoded .. (%2e%2e)."""
        assert has_path_traversal("%2e%2e/etc/passwd")
        assert has_path_traversal("%2E%2E/etc/passwd")

    def test_null_byte_detected(self):
        """Should detect null byte injection."""
        assert has_path_traversal("/path\x00.jpg")

    def test_normal_path_safe(self):
        """Normal paths should not be flagged."""
        assert not has_path_traversal("/normal/path/to/file")
        assert not has_path_traversal("/path/file.txt")


class TestSemanticURLComparison:
    """Tests for semantic URL comparison (improvement #9 round 2)."""

    def test_case_insensitive_scheme(self):
        """Different case schemes should be semantically equal."""
        url1 = parse_url("HTTP://example.com/path")
        url2 = parse_url("http://example.com/path")

        assert url1.is_semantically_equal(url2)

    def test_case_insensitive_host(self):
        """Different case hosts should be semantically equal."""
        url1 = parse_url("http://EXAMPLE.COM/path")
        url2 = parse_url("http://example.com/path")

        assert url1.is_semantically_equal(url2)

    def test_default_port_equivalence(self):
        """URLs with/without default port should be semantically equal."""
        url1 = parse_url("http://example.com:80/path")
        url2 = parse_url("http://example.com/path")

        assert url1.is_semantically_equal(url2)

    def test_different_ports_not_equal(self):
        """Different non-default ports should not be equal."""
        url1 = parse_url("http://example.com:8080/path")
        url2 = parse_url("http://example.com:9090/path")

        assert not url1.is_semantically_equal(url2)

    def test_different_paths_not_equal(self):
        """Different paths should not be equal."""
        url1 = parse_url("http://example.com/path1")
        url2 = parse_url("http://example.com/path2")

        assert not url1.is_semantically_equal(url2)

    def test_query_order_ignored(self):
        """Query parameter order should not affect equality."""
        url1 = parse_url("http://example.com/path?a=1&b=2")
        url2 = parse_url("http://example.com/path?b=2&a=1")

        # Both should have query pairs parsed
        assert len(url1.query_params) == 2
        assert len(url2.query_params) == 2

        # Canonical form should sort them the same
        canonical1 = url1.canonicalize()
        canonical2 = url2.canonicalize()

        assert canonical1.query == canonical2.query
        assert url1.is_semantically_equal(url2)


class TestAuditLogging:
    """Tests for audit logging (improvement #10 round 2)."""

    def setup_method(self):
        """Reset audit callback before each test."""
        set_audit_callback(None)

    def teardown_method(self):
        """Clean up audit callback after each test."""
        set_audit_callback(None)

    def test_set_audit_callback(self):
        """Should be able to set audit callback."""
        callback = Mock()
        set_audit_callback(callback)

        assert get_audit_callback() is callback

    def test_callback_on_success(self):
        """Callback should be called on successful parse."""
        callback = Mock()
        set_audit_callback(callback)

        parse_url("http://example.com/path")

        callback.assert_called_once()
        args = callback.call_args[0]
        assert args[0] == "http://example.com/path"  # raw url
        assert args[1] is not None  # parsed URL
        assert args[2] is None  # no exception

    def test_callback_on_failure(self):
        """Callback should be called on parse failure."""
        callback = Mock()
        set_audit_callback(callback)

        with pytest.raises((URLParseError, InvalidURLError)):
            # parse_url is now strict by default, use parse_url_unsafe with strict=True
            # or just use parse_url which is now strict
            parse_url("http://127.0.0.1/")

        callback.assert_called_once()
        args = callback.call_args[0]
        assert "127.0.0.1" in args[0]  # raw url
        assert args[1] is None  # no parsed URL
        assert args[2] is not None  # exception

    def test_disable_callback(self):
        """Should be able to disable callback."""
        callback = Mock()
        set_audit_callback(callback)
        set_audit_callback(None)

        parse_url("http://example.com/")

        callback.assert_not_called()

    def test_thread_safety_concurrent_parsing(self):
        """Audit callback should be thread-safe with concurrent URL parsing."""
        import threading

        results = []
        errors = []
        lock = threading.Lock()

        def thread_safe_callback(raw_url, parsed_url, exception):
            with lock:
                results.append((raw_url, parsed_url is not None, exception))

        set_audit_callback(thread_safe_callback)

        def parse_urls(thread_id):
            try:
                for i in range(10):
                    parse_url(f"http://example{thread_id}.com/path{i}")
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=parse_urls, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All parsing should succeed
        assert len(errors) == 0, f"Errors occurred: {errors}"
        # Should have 50 results (5 threads * 10 URLs each)
        assert len(results) == 50

    def test_thread_safety_callback_swap(self):
        """Swapping callbacks while parsing should not cause errors."""
        import threading

        errors = []
        call_count = {"a": 0, "b": 0}
        lock = threading.Lock()

        def callback_a(raw_url, parsed_url, exception):
            with lock:
                call_count["a"] += 1

        def callback_b(raw_url, parsed_url, exception):
            with lock:
                call_count["b"] += 1

        def parse_urls():
            try:
                for i in range(20):
                    parse_url(f"http://example.com/path{i}")
            except Exception as e:
                with lock:
                    errors.append(e)

        def swap_callbacks():
            for i in range(10):
                set_audit_callback(callback_a if i % 2 == 0 else callback_b)

        set_audit_callback(callback_a)

        parse_thread = threading.Thread(target=parse_urls)
        swap_thread = threading.Thread(target=swap_callbacks)

        parse_thread.start()
        swap_thread.start()

        parse_thread.join()
        swap_thread.join()

        # No errors should occur
        assert len(errors) == 0, f"Errors occurred: {errors}"
        # At least some callbacks should have been invoked
        assert call_count["a"] + call_count["b"] == 20


class TestCallbackFailureMetrics:
    """Tests for callback failure metrics tracking."""

    def setup_method(self):
        """Reset callback and metrics before each test."""
        set_audit_callback(None)
        reset_callback_failure_metrics()

    def teardown_method(self):
        """Clean up after each test."""
        set_audit_callback(None)
        reset_callback_failure_metrics()

    def test_initial_metrics_are_zero(self):
        """Initial failure count should be zero."""
        metrics = get_callback_failure_metrics()
        assert metrics["failure_count"] == 0
        assert metrics["last_error"] is None

    def test_failing_callback_increments_count(self):
        """Callback that raises should increment failure count."""
        def failing_callback(raw_url, parsed_url, exception):
            raise ValueError("Callback error")

        set_audit_callback(failing_callback)
        parse_url("http://example.com/")

        metrics = get_callback_failure_metrics()
        assert metrics["failure_count"] == 1
        assert isinstance(metrics["last_error"], ValueError)
        assert str(metrics["last_error"]) == "Callback error"

    def test_multiple_failures_tracked(self):
        """Multiple callback failures should be counted."""
        def failing_callback(raw_url, parsed_url, exception):
            raise RuntimeError("fail")

        set_audit_callback(failing_callback)

        for i in range(5):
            parse_url(f"http://example{i}.com/")

        metrics = get_callback_failure_metrics()
        assert metrics["failure_count"] == 5

    def test_last_error_is_most_recent(self):
        """last_error should be the most recent exception."""
        call_count = [0]

        def failing_callback(raw_url, parsed_url, exception):
            call_count[0] += 1
            raise ValueError(f"Error {call_count[0]}")

        set_audit_callback(failing_callback)

        parse_url("http://example1.com/")
        parse_url("http://example2.com/")
        parse_url("http://example3.com/")

        metrics = get_callback_failure_metrics()
        assert metrics["failure_count"] == 3
        assert str(metrics["last_error"]) == "Error 3"

    def test_successful_callback_does_not_increment(self):
        """Successful callback should not affect failure metrics."""
        def good_callback(raw_url, parsed_url, exception):
            pass  # Does nothing, doesn't raise

        set_audit_callback(good_callback)
        parse_url("http://example.com/")

        metrics = get_callback_failure_metrics()
        assert metrics["failure_count"] == 0
        assert metrics["last_error"] is None

    def test_reset_clears_metrics(self):
        """reset_callback_failure_metrics should clear all metrics."""
        def failing_callback(raw_url, parsed_url, exception):
            raise ValueError("fail")

        set_audit_callback(failing_callback)
        parse_url("http://example.com/")

        # Verify there's a failure
        assert get_callback_failure_metrics()["failure_count"] == 1

        # Reset and verify
        previous = reset_callback_failure_metrics()
        assert previous["failure_count"] == 1
        assert previous["last_error"] is not None

        metrics = get_callback_failure_metrics()
        assert metrics["failure_count"] == 0
        assert metrics["last_error"] is None

    def test_callback_failure_does_not_break_parsing(self):
        """Callback failure should not prevent URL from being parsed."""
        def failing_callback(raw_url, parsed_url, exception):
            raise Exception("This should not break parsing")

        set_audit_callback(failing_callback)

        # Should not raise, even though callback fails
        url = parse_url("http://example.com/path")
        assert url.host == "example.com"
        assert url.path == "/path"

    def test_thread_safety_of_metrics(self):
        """Metrics should be thread-safe."""
        import threading

        def failing_callback(raw_url, parsed_url, exception):
            raise ValueError("fail")

        set_audit_callback(failing_callback)

        def parse_many():
            for i in range(10):
                parse_url(f"http://example{i}.com/")

        threads = [threading.Thread(target=parse_many) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        metrics = get_callback_failure_metrics()
        # 5 threads * 10 URLs each = 50 failures
        assert metrics["failure_count"] == 50


class TestCheckDNSFlag:
    """Tests ensuring check_dns flag works independently."""

    def test_check_dns_false_by_default(self):
        """check_dns should be False by default in parse_url."""
        url = parse_url("http://example.com/")
        assert not url._check_dns

    def test_check_dns_can_be_enabled(self):
        """check_dns can be enabled explicitly."""
        url = parse_url("http://8.8.8.8/", check_dns=True)
        assert url._check_dns

    def test_check_dns_independent_of_strict(self):
        """check_dns and strict should work independently."""
        # parse_url is always strict now, use parse_url_unsafe for non-strict
        # strict=True, check_dns=False
        url1 = parse_url_unsafe("http://google.com/", strict=True, check_dns=False)
        assert url1._strict
        assert not url1._check_dns

        # strict=False, check_dns=True (on public IP)
        url2 = parse_url_unsafe("http://8.8.8.8/", strict=False, check_dns=True)
        assert not url2._strict
        assert url2._check_dns
