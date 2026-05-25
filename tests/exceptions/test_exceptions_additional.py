"""Additional exception behavior tests."""

from __future__ import annotations

class TestExceptions:
    def test_urlp_error_str_with_code_only(self):
        """Line 57: __str__ when code is set but no value/component."""
        from urlps.exceptions import URLpError, ErrorCode
        err = URLpError("test message", code=ErrorCode.SSRF_RISK)
        result = str(err)
        assert "ssrf_risk" in result
        assert "code=" in result

    def test_urlp_error_str_with_code_and_component(self):
        """Line 54: __str__ with code and component."""
        from urlps.exceptions import URLpError, ErrorCode
        err = URLpError("test message", value="bad_val", component="host", code=ErrorCode.SSRF_RISK)
        result = str(err)
        assert "code=" in result
        assert "component=" in result

    def test_urlp_error_str_basic(self):
        """Line 58: __str__ without code, without value/component."""
        from urlps.exceptions import URLpError
        err = URLpError("basic message")
        assert str(err) == "basic message"

    def test_urlp_error_str_component_only(self):
        """Line 55: __str__ with component but no code."""
        from urlps.exceptions import URLpError
        err = URLpError("msg", component="host")
        result = str(err)
        assert "component=" in result
        assert "code=" not in result
