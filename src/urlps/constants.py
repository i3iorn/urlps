from __future__ import annotations

from enum import Enum
from typing import Dict, Final, FrozenSet, Set
import os
import warnings


class OfficialSchemes(Enum):
    """Officially recognized URL schemes."""

    HTTP = "http"
    HTTPS = "https"
    FTP = "ftp"
    FTPS = "ftps"
    SFTP = "sftp"
    FILE = "file"
    WS = "ws"
    WSS = "wss"


DEFAULT_PORTS: Final[Dict[str, int]] = {
    OfficialSchemes.HTTP.value: 80,
    OfficialSchemes.HTTPS.value: 443,
    OfficialSchemes.FTP.value: 21,
    OfficialSchemes.FTPS.value: 990,
    OfficialSchemes.SFTP.value: 22,
    OfficialSchemes.WS.value: 80,
    OfficialSchemes.WSS.value: 443,
}

SCHEMES_NO_PORT: Final[Set[str]] = {OfficialSchemes.FILE.value}

OFFICIAL_SCHEMES: Final[FrozenSet[str]] = frozenset(s.value for s in OfficialSchemes)

UNSAFE_SCHEMES: Final[FrozenSet[str]] = frozenset(
    {
        "javascript",
        "data",
        "vbscript",  # Script execution
        "jar",
        "file",  # Local file access
        "gopher",
        "dict",
        "tftp",  # Protocol exploitation
        "ldap",
        "ldaps",  # Information disclosure
    }
)

STANDARD_PORTS: Final[FrozenSet[int]] = frozenset([80, 443, 21, 22, 25, 110, 143, 53])

DANGEROUS_PORTS: Final[FrozenSet[int]] = frozenset(
    {
        22,  # SSH
        23,  # Telnet
        25,  # SMTP
        110,  # POP3
        143,  # IMAP
        445,  # SMB
        3306,  # MySQL
        5432,  # PostgreSQL
        6379,  # Redis
        9200,  # Elasticsearch
        27017,  # MongoDB
        11211,  # Memcached
    }
)


def _get_positive_int_from_env(env_name: str, default: int) -> int:
    """Return a positive integer from environment or the provided default.

    Environment variables must be positive integers. Invalid values are ignored
    with a warning and the default is returned.
    """
    raw_value = os.getenv(env_name)
    if raw_value is None:
        return default

    try:
        parsed_value = int(raw_value)
    except ValueError:
        warnings.warn(
            f"Environment variable {env_name} must be an integer; ignoring value.",
            RuntimeWarning,
        )
        return default

    if parsed_value <= 0:
        warnings.warn(
            f"Environment variable {env_name} must be a positive integer; ignoring value.",
            RuntimeWarning,
        )
        return default

    return parsed_value


# Component length limits for security (tuned for 99.99% of URLs)
# These are intentionally conservative to reduce attack surface while
# still accommodating real-world usage (tracking, long query strings, etc.).
MAX_URL_LENGTH: Final[int] = _get_positive_int_from_env("URLPS_MAX_URL_LENGTH", 32 * 1024)
MAX_SCHEME_LENGTH: Final[int] = _get_positive_int_from_env("URLPS_MAX_SCHEME_LENGTH", 16)
MAX_HOST_LENGTH: Final[int] = _get_positive_int_from_env("URLPS_MAX_HOST_LENGTH", 253)
MAX_PATH_LENGTH: Final[int] = _get_positive_int_from_env("URLPS_MAX_PATH_LENGTH", 4 * 1024)
MAX_QUERY_LENGTH: Final[int] = _get_positive_int_from_env("URLPS_MAX_QUERY_LENGTH", 8 * 1024)
MAX_FRAGMENT_LENGTH: Final[int] = _get_positive_int_from_env("URLPS_MAX_FRAGMENT_LENGTH", 1 * 1024)
MAX_USERINFO_LENGTH: Final[int] = _get_positive_int_from_env("URLPS_MAX_USERINFO_LENGTH", 128)
MAX_IPV6_STRING_LENGTH: Final[int] = _get_positive_int_from_env("URLPS_MAX_IPV6_STRING_LENGTH", 128)

BLOCKED_HOSTNAMES: Final[FrozenSet[str]] = frozenset(  # nosec B104
    {
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
    }
)

DEFAULT_DNS_TIMEOUT: Final[float] = 2.0

# DNS Rate Limiting Configuration
# These values prevent DNS-based DoS attacks while allowing legitimate usage.
DEFAULT_DNS_LOOKUPS_PER_SECOND: Final[float] = 10.0  # Global rate limit
DEFAULT_DNS_LOOKUPS_PER_HOST: Final[int] = 3  # Per-hostname limit
DEFAULT_DNS_TIME_WINDOW_SECONDS: Final[float] = 60.0  # Time window for per-host tracking
DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS: Final[float] = 300.0  # Cleanup old tracking data

# Phishing Database Configuration
PHISHING_DATABASE_URL: Final[str] = "https://phish.co.za/latest/ALL-phishing-domains.lst"
DEFAULT_PHISHING_DATABASE_MAX_BYTES: Final[int] = 25 * 1024 * 1024

PASSWORD_MASK: Final[str] = "***"


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
    "DEFAULT_PHISHING_DATABASE_MAX_BYTES",
    "PASSWORD_MASK",
]
