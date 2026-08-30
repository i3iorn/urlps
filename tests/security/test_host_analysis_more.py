"""Additional coverage for _security/host_analysis.py edge cases."""

from __future__ import annotations

from urlps._security.host_analysis import analyze_host
from urlps.exceptions import ErrorCode


def test_empty_host_returns_no_findings():
    assert analyze_host("") == ()


def test_ipv6_literal_returns_no_findings():
    assert analyze_host("[::1]") == ()


def test_malformed_punycode_reports_invalid_punycode():
    findings = analyze_host("xn--!!!.com")
    assert len(findings) == 1
    code, severity, _ = findings[0]
    assert code == ErrorCode.INVALID_PUNYCODE
    assert severity == "critical"
