"""Tests for dangerous port validation."""
import pytest
from urlps._security import is_dangerous_port
from urlps.constants import DANGEROUS_PORTS


class TestDangerousPorts:
    """Test dangerous port validation."""

    def test_dangerous_ports_defined(self):
        """Verify dangerous ports are defined."""
        expected = {22, 23, 25, 110, 143, 445, 3306, 5432, 6379, 9200, 27017, 11211}
        assert expected.issubset(DANGEROUS_PORTS)

    def test_dangerous_port_when_flag_true(self):
        """Dangerous ports should be blocked when flag is True."""
        assert is_dangerous_port(22, block_dangerous_ports=True)  # SSH
        assert is_dangerous_port(3306, block_dangerous_ports=True)  # MySQL
        assert is_dangerous_port(6379, block_dangerous_ports=True)  # Redis
        assert is_dangerous_port(27017, block_dangerous_ports=True)  # MongoDB

    def test_dangerous_port_when_flag_false(self):
        """Dangerous ports should be allowed when flag is False."""
        assert not is_dangerous_port(22, block_dangerous_ports=False)
        assert not is_dangerous_port(3306, block_dangerous_ports=False)

    def test_dangerous_port_default_behavior(self):
        """Default behavior should allow dangerous ports (backward compat)."""
        assert not is_dangerous_port(22)  # Default is False
        assert not is_dangerous_port(3306)

    def test_safe_ports_always_allowed(self):
        """Safe ports should always be allowed."""
        assert not is_dangerous_port(80, block_dangerous_ports=True)
        assert not is_dangerous_port(443, block_dangerous_ports=True)
        assert not is_dangerous_port(8080, block_dangerous_ports=True)

    def test_none_port_allowed(self):
        """None port should always be allowed."""
        assert not is_dangerous_port(None, block_dangerous_ports=True)
        assert not is_dangerous_port(None, block_dangerous_ports=False)


class TestDangerousPortsScenarios:
    """Test real-world scenarios with dangerous ports."""

    def test_ssrf_to_database(self):
        """SSRF to database ports."""
        assert is_dangerous_port(3306, block_dangerous_ports=True)  # MySQL
        assert is_dangerous_port(5432, block_dangerous_ports=True)  # PostgreSQL
        assert is_dangerous_port(27017, block_dangerous_ports=True)  # MongoDB

    def test_ssrf_to_cache(self):
        """SSRF to cache servers."""
        assert is_dangerous_port(6379, block_dangerous_ports=True)  # Redis
        assert is_dangerous_port(11211, block_dangerous_ports=True)  # Memcached

    def test_ssrf_to_elasticsearch(self):
        """SSRF to Elasticsearch."""
        assert is_dangerous_port(9200, block_dangerous_ports=True)

    def test_ssh_telnet_blocked(self):
        """SSH and Telnet should be blocked."""
        assert is_dangerous_port(22, block_dangerous_ports=True)  # SSH
        assert is_dangerous_port(23, block_dangerous_ports=True)  # Telnet
