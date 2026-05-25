"""Additional security policy resolution tests."""

from __future__ import annotations

import pytest
from urlps.exceptions import SecurityPolicyError

class TestSecurityPolicy:
    def test_resolve_security_policy_with_security_policy_instance(self):
        """Line 77: resolve with SecurityPolicy instance returns it directly."""
        from urlps._security.policy import SecurityPolicy, resolve_security_policy
        policy = SecurityPolicy.strict()
        resolved = resolve_security_policy(policy)
        assert resolved is policy

    def test_resolve_security_policy_internal(self):
        """Lines 84-87: resolve with 'internal' string."""
        from urlps._security.policy import resolve_security_policy
        resolved = resolve_security_policy("internal")
        assert resolved.name == "internal"
        assert resolved.enforce_ssrf is False

    def test_resolve_security_policy_none_returns_balanced(self):
        """resolve with None returns balanced policy."""
        from urlps._security.policy import resolve_security_policy
        resolved = resolve_security_policy(None)
        assert resolved.name == "balanced"

    def test_resolve_security_policy_strict_string(self):
        """resolve with 'strict' string."""
        from urlps._security.policy import resolve_security_policy
        resolved = resolve_security_policy("strict")
        assert resolved.name == "strict"

    def test_resolve_security_policy_unsupported_raises(self):
        """resolve with invalid string raises ValueError."""
        from urlps._security.policy import resolve_security_policy
        with pytest.raises(SecurityPolicyError, match="Unsupported security policy"):
            resolve_security_policy("invalid_policy")

    def test_resolve_security_policy_returns_resolved_when_no_overrides(self):
        """Line 112: returns resolved without rebuilding when no dns/phishing overrides."""
        from urlps._security.policy import SecurityPolicy, resolve_security_policy
        policy = SecurityPolicy.strict()
        resolved = resolve_security_policy(policy, check_dns=None, check_phishing=None)
        assert resolved is policy

    def test_resolve_security_policy_with_check_dns_override(self):
        """check_dns override creates new policy with check_dns=True."""
        from urlps._security.policy import resolve_security_policy
        resolved = resolve_security_policy("strict", check_dns=True)
        assert resolved.check_dns is True

    def test_resolve_security_policy_with_check_phishing_override(self):
        """check_phishing override creates new policy with check_phishing=True."""
        from urlps._security.policy import resolve_security_policy
        resolved = resolve_security_policy("balanced", check_phishing=True)
        assert resolved.check_phishing is True
