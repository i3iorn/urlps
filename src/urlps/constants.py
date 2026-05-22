from __future__ import annotations

from enum import Enum
from typing import Dict, FrozenSet, Set
import os
import warnings


class OfficialSchemes(Enum):
    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    FTPS = "ftps"
    SFTP = "sftp"
    FILE = "file"
    WS = "ws"
    WSS = "wss"


DEFAULT_PORTS: Dict[str, int] = {
    OfficialSchemes.HTTP.value: 80,
    OfficialSchemes.HTTPS.value: 443,
    OfficialSchemes.FTP.value: 21,
    OfficialSchemes.FTPS.value: 990,
    OfficialSchemes.SFTP.value: 22,
    OfficialSchemes.WS.value: 80,
    OfficialSchemes.WSS.value: 443,
}

SCHEMES_NO_PORT: Set[str] = {OfficialSchemes.FILE.value}

OFFICIAL_SCHEMES: FrozenSet[str] = frozenset(s.value for s in OfficialSchemes)
UNSAFE_SCHEMES: FrozenSet[str] = frozenset({
    "javascript", "data", "vbscript",  # Script execution
    "jar", "file",  # Local file access
    "gopher", "dict", "tftp",  # Protocol exploitation
    "ldap", "ldaps",  # Information disclosure
})

STANDARD_PORTS: FrozenSet[int] = frozenset([80, 443, 21, 22, 25, 110, 143, 53])

DANGEROUS_PORTS: FrozenSet[int] = frozenset({
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    110,   # POP3
    143,   # IMAP
    445,   # SMB
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    9200,  # Elasticsearch
    27017, # MongoDB
    11211, # Memcached
})

# Component length limits for security (tuned for 99.99% of URLs)
# These are intentionally conservative to reduce attack surface while
# still accommodating real-world usage (tracking, long query strings, etc.).
MAX_URL_LENGTH = 32 * 1024
MAX_SCHEME_LENGTH = 16
MAX_HOST_LENGTH = 253
MAX_PATH_LENGTH = 4 * 1024
MAX_QUERY_LENGTH = 8 * 1024
MAX_FRAGMENT_LENGTH = 1 * 1024
MAX_USERINFO_LENGTH = 128
MAX_IPV6_STRING_LENGTH = 128

_ENV_OVERRIDES = {
    "MAX_URL_LENGTH": "URLPS_MAX_URL_LENGTH",
    "MAX_SCHEME_LENGTH": "URLPS_MAX_SCHEME_LENGTH",
    "MAX_HOST_LENGTH": "URLPS_MAX_HOST_LENGTH",
    "MAX_PATH_LENGTH": "URLPS_MAX_PATH_LENGTH",
    "MAX_QUERY_LENGTH": "URLPS_MAX_QUERY_LENGTH",
    "MAX_FRAGMENT_LENGTH": "URLPS_MAX_FRAGMENT_LENGTH",
    "MAX_USERINFO_LENGTH": "URLPS_MAX_USERINFO_LENGTH",
    "MAX_IPV6_STRING_LENGTH": "URLPS_MAX_IPV6_STRING_LENGTH",
}


def _apply_env_overrides() -> None:
    """Apply environment-variable overrides to module-level max-size constants.

    Environment variables are named like `URLPS_MAX_URL_LENGTH`. Values must be
    positive integers. Invalid or non-positive values are ignored with a warning.
    """
    for const_name, env_name in _ENV_OVERRIDES.items():
        val = os.getenv(env_name)
        if val is None:
            continue
        try:
            iv = int(val)
        except Exception:
            warnings.warn(f"Environment variable {env_name} value '{val}' is not an integer; ignoring.")
            continue
        if iv <= 0:
            warnings.warn(f"Environment variable {env_name} must be a positive integer; ignoring value {iv}.")
            continue
        # Set the module-level constant
        globals()[const_name] = iv


_apply_env_overrides()

BLOCKED_HOSTNAMES: FrozenSet[str] = frozenset({  # nosec B104
    # Localhost variations
    "localhost",
    "localhost.localdomain",
    "localhost.",
    # IPv4 loopback and special addresses
    "127.0.0.1",
    "0.0.0.0",
    # IPv6 loopback
    "::1",
    "[::1]",
    "[::]",
    "[0:0:0:0:0:0:0:1]",
    "[0000:0000:0000:0000:0000:0000:0000:0001]",
    # Cloud metadata endpoints (AWS, GCP, Azure, etc.)
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "169.254.170.2",
    "169.254.0.0",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
})

DEFAULT_DNS_TIMEOUT: float = 2.0

# DNS Rate Limiting Configuration
# These values prevent DNS-based DoS attacks while allowing legitimate usage
DEFAULT_DNS_LOOKUPS_PER_SECOND: float = 10.0  # Global rate limit
DEFAULT_DNS_LOOKUPS_PER_HOST: int = 3  # Per-hostname limit
DEFAULT_DNS_TIME_WINDOW_SECONDS: float = 60.0  # Time window for per-host tracking
DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS: float = 300.0  # Cleanup old tracking data

# Phishing Database Configuration
PHISHING_DATABASE_URL: str = "https://phish.co.za/latest/ALL-phishing-domains.lst"

PASSWORD_MASK: str = "***"


__all__ = [
    "OfficialSchemes",
    "DEFAULT_PORTS",
    "SCHEMES_NO_PORT",
    "OFFICIAL_SCHEMES",
    "DANGEROUS_PORTS",
    "UNSAFE_SCHEMES",
    "STANDARD_PORTS",
    "MAX_URL_LENGTH",
    "MAX_SCHEME_LENGTH",
    "MAX_HOST_LENGTH",
    "MAX_PATH_LENGTH",
    "MAX_QUERY_LENGTH",
    "MAX_FRAGMENT_LENGTH",
    "MAX_USERINFO_LENGTH",
    "MAX_IPV6_STRING_LENGTH",
    "BLOCKED_HOSTNAMES",
    "DEFAULT_DNS_TIMEOUT",
    "DEFAULT_DNS_LOOKUPS_PER_SECOND",
    "DEFAULT_DNS_LOOKUPS_PER_HOST",
    "DEFAULT_DNS_TIME_WINDOW_SECONDS",
    "DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS",
    "PHISHING_DATABASE_URL",
    "PASSWORD_MASK",
]
