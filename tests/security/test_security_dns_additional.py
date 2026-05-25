"""Additional DNS security tests."""

from __future__ import annotations

class TestSecurityDNS:
    def test_check_dns_rebinding_detailed_empty_host(self):
        """Line 230: empty host returns DNS_RESOLUTION_FAILED."""
        from src.urlps._security import check_dns_rebinding_detailed
        from src.urlps.exceptions import ErrorCode
        safe, error = check_dns_rebinding_detailed("")
        assert safe is False
        assert error == ErrorCode.DNS_RESOLUTION_FAILED

    def test_check_dns_rebinding_detailed_private_ip_direct(self):
        """Lines 232->234 branch: private IP detected directly."""
        from src.urlps._security import check_dns_rebinding_detailed
        from src.urlps.exceptions import ErrorCode
        safe, error = check_dns_rebinding_detailed("127.0.0.1")
        assert safe is False
        assert error == ErrorCode.SSRF_RISK

    def test_check_dns_rebinding_detailed_safe_direct_ip(self):
        """Lines 232->234 branch: safe IP detected directly returns True."""
        from src.urlps._security import check_dns_rebinding_detailed
        safe, error = check_dns_rebinding_detailed("93.184.216.34")  # example.com
        assert safe is True
        assert error is None
