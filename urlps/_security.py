"""Unified security checks for URL validation (SSRF, path traversal, homograph attacks).

Naming Convention:
    - is_*(): Pure predicates returning bool (e.g., is_ssrf_risk, is_private_ip)
    - has_*(): Predicates checking for presence of patterns (e.g., has_mixed_scripts, has_double_encoding)
    - check_*(): Functions with side effects like DNS lookups (e.g., check_dns_rebinding)
    - validate_*(): Functions that raise exceptions on failure (e.g., validate_url_security)

All functions are designed to be defensive - returning False on invalid input types
rather than raising exceptions, except for validate_* functions.
"""
from __future__ import annotations

import ipaddress
import socket
import time
import unicodedata
from collections import defaultdict, deque
from functools import lru_cache
from typing import Optional, Set, Tuple, Union, Deque, Dict
from urllib import request
from urllib.error import URLError
from urllib.parse import unquote

from .constants import (
    BLOCKED_HOSTNAMES,
    DEFAULT_DNS_TIMEOUT,
    DANGEROUS_PORTS,
    DEFAULT_DNS_LOOKUPS_PER_SECOND,
    DEFAULT_DNS_LOOKUPS_PER_HOST,
    DEFAULT_DNS_TIME_WINDOW_SECONDS,
    DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS,
    PHISHING_DATABASE_URL,
)
from ._patterns import PATTERNS


def _is_ip_safe(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Check if IP is safe (not private/reserved)."""
    return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_link_local)


def _check_ipv4_private(host: str) -> bool:
    """Check if IPv4 address is private/reserved."""
    try:
        return not _is_ip_safe(ipaddress.IPv4Address(host))
    except (ValueError, ipaddress.AddressValueError):
        return False


def _check_ipv6_private(host: str) -> bool:
    """Check if IPv6 address (bracketed) is private/reserved."""
    if not host.startswith("[") or not host.endswith("]"):
        return False
    try:
        inner = _strip_ipv6_brackets(host)
        return not _is_ip_safe(ipaddress.IPv6Address(inner))
    except (ValueError, ipaddress.AddressValueError):
        return False


def _strip_ipv6_brackets(host: str) -> str:
    """Strip brackets and zone ID from IPv6 address."""
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
        if '%25' in host:
            host, _, _ = host.partition('%25')
    return host


def _is_blocked_hostname(host_lower: str) -> bool:
    """Check if hostname is in the blocklist."""
    if host_lower in BLOCKED_HOSTNAMES:
        return True
    return host_lower.endswith('.local') or host_lower.endswith('.localhost') or host_lower.endswith('.internal')


def _is_ipv4_mapped_ipv6(host_lower: str) -> bool:
    """Check for IPv4-mapped IPv6 addresses."""
    return host_lower.startswith('[::ffff:')


def _parse_ip_octet(part: str) -> Optional[int]:
    """Parse IP octet in decimal, octal, or hex format."""
    part_lower = part.lower()
    try:
        if part_lower.startswith('0x'):
            return int(part_lower, 16)
        elif part.startswith('0') and len(part) > 1 and part.isdigit():
            return int(part, 8)
        elif part.isdigit():
            return int(part)
    except ValueError:
        pass
    return None


def _is_decimal_ip_private(host: str) -> bool:
    """Check decimal IP format (e.g., 2130706433 = 127.0.0.1)."""
    if not host.isdigit():
        return False
    try:
        decimal_ip = int(host)
        if 0 <= decimal_ip <= 0xFFFFFFFF:
            ip_str = '.'.join(str(b) for b in decimal_ip.to_bytes(4, 'big'))
            return not _is_ip_safe(ipaddress.IPv4Address(ip_str))
    except (ValueError, OverflowError, ipaddress.AddressValueError):
        pass
    return False


def _is_octal_hex_ip_private(host: str) -> bool:
    """Check octal/hex IP format (e.g., 0177.0.0.1)."""
    if '.' not in host:
        return False
    parts = host.split('.')
    if len(parts) != 4:
        return False
    octets = []
    for part in parts:
        octet = _parse_ip_octet(part)
        if octet is None:
            return False
        octets.append(octet)
    if not all(0 <= o <= 255 for o in octets):
        return False
    try:
        return not _is_ip_safe(ipaddress.IPv4Address('.'.join(str(o) for o in octets)))
    except (ValueError, ipaddress.AddressValueError):
        return False


def _check_direct_ip_safe(host: str) -> Optional[bool]:
    """Check if host is a direct IP and if it's safe. Returns None if not IP."""
    try:
        return _is_ip_safe(ipaddress.ip_address(host))
    except ValueError:
        return None


def _check_resolved_ips_safe(addr_info) -> bool:
    """Check if all resolved IPs are safe."""
    for family, socktype, proto, _, sockaddr in addr_info:
        try:
            if not _is_ip_safe(ipaddress.ip_address(sockaddr[0])):
                return False
        except ValueError:
            continue
    return True


def _verify_connection_safe(addr_info, timeout: float) -> bool:
    """Verify connection is safe against DNS rebinding."""
    if not addr_info:
        return True
    family, socktype, proto, _, sockaddr = addr_info[0]
    test_sock = socket.socket(family, socktype, proto)
    try:
        test_sock.settimeout(timeout)
        test_sock.connect(sockaddr)
        try:
            return _is_ip_safe(ipaddress.ip_address(test_sock.getpeername()[0]))
        except ValueError:
            return True
    except (socket.timeout, OSError):
        return True
    finally:
        test_sock.close()


@lru_cache(maxsize=512)
def is_private_ip(host: str) -> bool:
    """Check if host is a private/reserved IP address."""
    if not isinstance(host, str):
        return False
    return _check_ipv4_private(host) or _check_ipv6_private(host)


@lru_cache(maxsize=512)
def is_ssrf_risk(host: str) -> bool:
    """Check if host poses SSRF risk (blocked hostnames, private IPs, etc.)."""
    if not isinstance(host, str) or not host:
        return False
    host_lower = host.lower().rstrip('.')
    return (_is_blocked_hostname(host_lower) or _is_ipv4_mapped_ipv6(host_lower) or
            _is_decimal_ip_private(host) or _is_octal_hex_ip_private(host) or is_private_ip(host))


def check_dns_rebinding(host: str, timeout: Optional[float] = None, enforce_rate_limit: bool = True) -> bool:
    """Check if hostname resolves to safe (non-private) IPs.

    Args:
        host: The hostname to check
        timeout: DNS lookup timeout in seconds
        enforce_rate_limit: If True, apply DNS rate limiting

    Returns:
        True if hostname is safe, False otherwise
    """
    if not isinstance(host, str) or not host:
        return False

    # Check rate limit if enabled
    if enforce_rate_limit:
        limiter = get_dns_rate_limiter()
        if not limiter.is_allowed(host):
            # Rate limited - return False to prevent lookup
            return False

    if timeout is None:
        timeout = DEFAULT_DNS_TIMEOUT
    host = _strip_ipv6_brackets(host)
    direct_result = _check_direct_ip_safe(host)
    if direct_result is not None:
        return direct_result
    try:
        addr_info = socket.getaddrinfo(host, 80, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not _check_resolved_ips_safe(addr_info):
            return False
        return _verify_connection_safe(addr_info, timeout)
    except (socket.gaierror, socket.timeout, OSError):
        return False

PHISHING_SET: Optional[Set[str]] = None

def check_against_phishing_db(host: str) -> bool:
    """Check if hostname is in known phishing database."""
    global PHISHING_SET
    if PHISHING_SET is None:
        PHISHING_SET = _download_phishing_db()
    if not isinstance(host, str):
        return False
    host_lower = host.lower().rstrip('.')
    return host_lower in PHISHING_SET


def refresh_phishing_db() -> int:
    """Refresh the phishing database cache.

    Forces a re-download of the phishing database from the remote source.
    This is useful for long-running applications that need fresh data.

    Returns:
        The number of hostnames in the refreshed database.

    Example:
        >>> refresh_phishing_db()
        12345
    """
    global PHISHING_SET
    PHISHING_SET = _download_phishing_db()
    return len(PHISHING_SET)


def get_phishing_db_info() -> dict:
    """Get information about the current phishing database cache.

    Returns:
        Dict containing:
            - loaded: Whether the database has been loaded
            - size: Number of hostnames in the database (0 if not loaded)
    """
    return {
        "loaded": PHISHING_SET is not None,
        "size": len(PHISHING_SET) if PHISHING_SET is not None else 0,
    }


def _download_phishing_db() -> Set[str]:
    """Download and return a set of known phishing hostnames.

    The database URL can be configured via the PHISHING_DATABASE_URL constant.
    """
    try:
        response = request.urlopen(PHISHING_DATABASE_URL, timeout=DEFAULT_DNS_TIMEOUT)
        if response.status != 200:
            return set()
        content = response.read().decode('utf-8', errors='ignore')
        hostnames = {line.strip().lower() for line in content.splitlines() if line.strip()}
        return hostnames
    except (URLError, socket.timeout, OSError, ValueError):
        return set()


@lru_cache(maxsize=512)
def has_mixed_scripts(host: str) -> bool:
    """Detect potential homograph attacks using mixed Unicode scripts.

    Performance: LRU cached and with fast-path for ASCII-only hosts.
    """
    if not isinstance(host, str):
        return False
    try:
        host.encode('ascii')
        return False
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass

    try:
        import unicodedata
        scripts: Set[str] = set()
        tracked = frozenset({'LATIN', 'CYRILLIC', 'GREEK', 'ARMENIAN', 'HEBREW',
                            'ARABIC', 'THAI', 'HANGUL', 'HIRAGANA', 'KATAKANA', 'CJK'})
        for char in host:
            if char.isalpha():
                name = unicodedata.name(char, '')
                if name:
                    script = name.split()[0]
                    if script in tracked:
                        scripts.add(script)
        return len(scripts) > 1
    except (ValueError, KeyError):
        return False


def has_double_encoding(value: str) -> bool:
    """Detect potential double-encoding attacks."""
    if not isinstance(value, str):
        return False
    return bool(PATTERNS["double_encode"].search(value))


def has_path_traversal(path: str) -> bool:
    """Detect path traversal attempts (.., null bytes, encoded variants)."""
    if not isinstance(path, str):
        return False
    if '..' in path or '\x00' in path:
        return True
    try:
        decoded = unquote(path)
        if '..' in decoded or '\x00' in decoded:
            return True
        if '..' in unquote(decoded):
            return True
    except (ValueError, UnicodeDecodeError):
        pass
    return False


def is_open_redirect_risk(path: str) -> bool:
    """Check if path could cause an open redirect (//, backslash)."""
    if not isinstance(path, str):
        return False
    return '\\' in path or path.startswith('//')


def is_malicious_ipv6_zone_id(host: str) -> bool:
    """Check if IPv6 zone identifier contains malicious content.

    Zone identifiers should only contain alphanumeric characters, dash, underscore,
    dot, and tilde per RFC 6874.
    """
    if not isinstance(host, str):
        return False

    if '%25' not in host and '%' not in host:
        return False

    if not (host.startswith('[') and ']' in host):
        return False

    try:
        inner = host[1:host.index(']')]
        if '%25' in inner or '%' in inner:
            zone_id = inner.split('%25' if '%25' in inner else '%', 1)[1]
            if not zone_id:
                return True
            for char in zone_id:
                if not (char.isalnum() or char in '-_.~'):
                    return True
    except (ValueError, IndexError):
        return True

    return False


def _has_mixed_path_separators(after_scheme: str) -> bool:
    """Check if URL has mixed forward slashes and backslashes.

    Some parsers treat backslash as forward slash, creating parser confusion.
    Example: http://example.com\/path is ambiguous.
    """
    return '/' in after_scheme and '\\' in after_scheme


def _has_slash_before_domain_dot(after_scheme: str) -> bool:
    """Check if forward slash appears before first dot in hostname.

    This indicates unusual structure that may confuse parsers about authority boundaries.
    Example: http://example/com is ambiguous (is 'example' the full host?).
    """
    slash_pos = after_scheme.find('/')
    dot_pos = after_scheme.find('.')
    return slash_pos != -1 and dot_pos != -1 and slash_pos < dot_pos


def _extract_authority_and_rest(after_scheme: str) -> Tuple[str, str]:
    """Extract authority component and remaining URL parts.

    Authority ends at first occurrence of '/', '?', or '#'.
    Returns (authority, rest) tuple.
    """
    end = len(after_scheme)
    for terminator in ('/', '?', '#'):
        idx = after_scheme.find(terminator)
        if idx != -1:
            end = min(end, idx)
    return after_scheme[:end], after_scheme[end:]


def _has_component_ordering_confusion(rest: str) -> bool:
    """Check if query or fragment appears before path.

    Standard order is path -> query -> fragment. Deviation may confuse parsers.
    Example: http://example.com#fragment/path is ambiguous.
    """
    if '#' in rest:
        slash_pos = rest.find('/')
        hash_pos = rest.find('#')
        if slash_pos == -1 or hash_pos < slash_pos:
            return True

    if '?' in rest:
        slash_pos = rest.find('/')
        query_pos = rest.find('?')
        if slash_pos == -1 or query_pos < slash_pos:
            return True

    return False


def _has_multiple_at_symbols(authority: str) -> bool:
    """Check if authority has multiple '@' symbols.

    Multiple @ symbols create ambiguity about userinfo parsing.
    Example: http://user@host@attacker.com is ambiguous.
    """
    return authority.count('@') > 1


def _has_confusing_userinfo_markers(authority: str) -> bool:
    """Check if authority terminators appear before '@' symbol.

    When '/', '?', or '#' appear before '@', parsers may disagree about
    whether '@' belongs to userinfo or path component.
    Example: http://user/path@host is ambiguous.
    """
    at_count = authority.count('@')
    if at_count == 0:
        return False

    before_last_at, _ = authority.rsplit('@', 1)
    return any(terminator in before_last_at for terminator in ('/', '?', '#'))


def has_parser_confusion(url: str) -> bool:
    """Detect ambiguous URLs that could be parsed differently by different parsers.

    This function implements conservative heuristics to identify URLs that may be
    interpreted differently across URL parsers, which attackers exploit to bypass
    security filters. False positives are acceptable to maintain security.

    Detection Categories:
    - Mixed separators: Backslash and forward slash usage
    - Authority boundary confusion: Unusual placement of path/query/fragment markers
    - Userinfo ambiguity: Multiple '@' symbols or misplaced terminators

    Args:
        url: The URL string to analyze

    Returns:
        True if the URL structure is ambiguous, False if unambiguous

    Note:
        Only checks raw characters, not percent-encoded equivalents (e.g., %40 for @).
    """
    if not isinstance(url, str) or '://' not in url:
        return False

    after_scheme = url.split('://', 1)[1]

    # Check for mixed separator confusion
    if _has_mixed_path_separators(after_scheme):
        return True

    if _has_slash_before_domain_dot(after_scheme):
        return True

    # Extract and analyze authority component
    authority, rest = _extract_authority_and_rest(after_scheme)

    if _has_component_ordering_confusion(rest):
        return True

    if not authority:
        return False

    # Backslash in authority is always suspicious
    if '\\' in authority:
        return True

    # Check for userinfo-related confusion
    if _has_multiple_at_symbols(authority):
        return True

    if _has_confusing_userinfo_markers(authority):
        return True

    return False


class DNSRateLimiter:
    """Rate limiter for DNS lookups to prevent DoS attacks.

    DNS lookups can be expensive and slow. Attackers might provide many URLs
    with unique hostnames to trigger excessive DNS queries, causing:
    - Resource exhaustion (CPU, network, file descriptors)
    - Network flooding
    - Upstream DNS server overload
    - Application slowdown/unavailability

    This rate limiter uses a token bucket algorithm with per-host tracking
    to prevent abuse while allowing legitimate usage.

    Attributes:
        max_lookups_per_second: Maximum DNS lookups allowed per second (globally)
        max_lookups_per_host: Maximum lookups for the same host in time_window
        time_window: Time window in seconds for per-host limits
        cleanup_interval: Seconds between cleanup of old tracking data
    """

    def __init__(
        self,
        max_lookups_per_second: float = DEFAULT_DNS_LOOKUPS_PER_SECOND,
        max_lookups_per_host: int = DEFAULT_DNS_LOOKUPS_PER_HOST,
        time_window: float = DEFAULT_DNS_TIME_WINDOW_SECONDS,
        cleanup_interval: float = DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS
    ):
        """Initialize DNS rate limiter.

        Args:
            max_lookups_per_second: Global rate limit (lookups/second).
                Default from constants.DEFAULT_DNS_LOOKUPS_PER_SECOND.
            max_lookups_per_host: Max lookups for same host in time_window.
                Default from constants.DEFAULT_DNS_LOOKUPS_PER_HOST.
            time_window: Seconds for per-host rate limit window.
                Default from constants.DEFAULT_DNS_TIME_WINDOW_SECONDS.
            cleanup_interval: Seconds between cleanup of old data.
                Default from constants.DEFAULT_DNS_CLEANUP_INTERVAL_SECONDS.
        """
        self.max_lookups_per_second = max_lookups_per_second
        self.max_lookups_per_host = max_lookups_per_host
        self.time_window = time_window
        self.cleanup_interval = cleanup_interval

        # Token bucket for global rate limit
        self.tokens = max_lookups_per_second
        self.last_update = time.time()

        # Per-host tracking: hostname -> deque of timestamps
        self.host_lookups: Dict[str, Deque[float]] = defaultdict(deque)

        # Cleanup tracking
        self.last_cleanup = time.time()

    def _refill_tokens(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(
            self.max_lookups_per_second,
            self.tokens + elapsed * self.max_lookups_per_second
        )
        self.last_update = now

    def _cleanup_old_entries(self) -> None:
        """Remove old entries to prevent memory leak."""
        now = time.time()
        if now - self.last_cleanup < self.cleanup_interval:
            return

        # Remove timestamps older than time_window
        cutoff = now - self.time_window
        hosts_to_remove = []

        for host, timestamps in self.host_lookups.items():
            # Remove old timestamps
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()
            # If no recent lookups, mark for removal
            if not timestamps:
                hosts_to_remove.append(host)

        # Remove empty hosts
        for host in hosts_to_remove:
            del self.host_lookups[host]

        self.last_cleanup = now

    def is_allowed(self, host: str) -> bool:
        """Check if a DNS lookup for this host is allowed.

        Args:
            host: The hostname to check

        Returns:
            True if lookup is allowed, False if rate limited

        Example:
            >>> limiter = DNSRateLimiter()
            >>> limiter.is_allowed("example.com")
            True
            >>> # After many requests...
            >>> limiter.is_allowed("example.com")
            False  # Rate limited
        """
        if not isinstance(host, str) or not host:
            return False

        now = time.time()

        # Check global rate limit (token bucket)
        self._refill_tokens()
        if self.tokens < 1.0:
            return False

        # Check per-host rate limit
        timestamps = self.host_lookups[host]

        # Remove timestamps outside the time window
        cutoff = now - self.time_window
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        # Check if host has exceeded its limit
        if len(timestamps) >= self.max_lookups_per_host:
            return False

        # Allow the lookup
        self.tokens -= 1.0
        timestamps.append(now)

        # Periodic cleanup
        self._cleanup_old_entries()

        return True

    def record_lookup(self, host: str) -> None:
        """Record that a DNS lookup was performed (without checking limits).

        Use this when you want to track lookups that were performed through
        other means (e.g., cached results) to maintain accurate rate limiting.

        Args:
            host: The hostname that was looked up
        """
        if not isinstance(host, str) or not host:
            return

        now = time.time()
        self.host_lookups[host].append(now)
        self._cleanup_old_entries()

    def reset(self) -> None:
        """Reset all rate limiting state."""
        self.tokens = self.max_lookups_per_second
        self.last_update = time.time()
        self.host_lookups.clear()
        self.last_cleanup = time.time()

    def get_stats(self) -> dict:
        """Get current rate limiter statistics.

        Returns:
            Dict with statistics:
                - tokens: Current token count
                - tracked_hosts: Number of hosts being tracked
                - total_recent_lookups: Total lookups in time window
        """
        self._refill_tokens()
        total_lookups = sum(len(timestamps) for timestamps in self.host_lookups.values())
        return {
            "tokens": self.tokens,
            "tracked_hosts": len(self.host_lookups),
            "total_recent_lookups": total_lookups,
        }


# Global DNS rate limiter instance
_dns_rate_limiter: Optional[DNSRateLimiter] = None


def get_dns_rate_limiter() -> DNSRateLimiter:
    """Get or create the global DNS rate limiter.

    Returns:
        The global DNSRateLimiter instance
    """
    global _dns_rate_limiter
    if _dns_rate_limiter is None:
        _dns_rate_limiter = DNSRateLimiter()
    return _dns_rate_limiter


def reset_dns_rate_limiter() -> None:
    """Reset the global DNS rate limiter.

    Useful for testing or when you want to clear all rate limiting state.
    """
    global _dns_rate_limiter
    if _dns_rate_limiter is not None:
        _dns_rate_limiter.reset()


def check_dns_rate_limit(host: str) -> bool:
    """Check if DNS lookup for this host is allowed under rate limits.

    This is a convenience function that uses the global rate limiter.

    Args:
        host: The hostname to check

    Returns:
        True if lookup is allowed, False if rate limited

    Example:
        >>> check_dns_rate_limit("example.com")
        True
        >>> # After many rapid requests...
        >>> check_dns_rate_limit("example.com")
        False  # Rate limited
    """
    limiter = get_dns_rate_limiter()
    return limiter.is_allowed(host)


def is_non_canonical_url(url: str) -> bool:
    """Detect URLs that are not in canonical form.

    Non-canonical URLs can be used to bypass security filters, cache systems,
    and access control mechanisms. Canonical form ensures consistent URL
    representation and prevents evasion techniques.

    Detects:
    1. Unnecessary percent-encoding (e.g., %41 for 'A')
    2. Case variations in scheme/host (e.g., HTTP vs http)
    3. Unnecessary port numbers (e.g., http://example.com:80)
    4. Non-normalized paths (e.g., /./path, /path/../other)
    5. Trailing dots in hostnames (e.g., example.com.)
    6. Mixed case in percent-encoding (e.g., %2f vs %2F)
    7. IPv6 address not in canonical form

    Args:
        url: The URL string to check

    Returns:
        True if URL is not in canonical form, False if canonical

    Examples:
        >>> is_non_canonical_url("HTTP://EXAMPLE.COM")  # Uppercase scheme/host
        True
        >>> is_non_canonical_url("http://example.com:80")  # Default port
        True
        >>> is_non_canonical_url("http://example.com/path/..")  # Non-normalized path
        True
        >>> is_non_canonical_url("http://example.com")  # Canonical
        False
    """
    if not isinstance(url, str) or not url:
        return False

    # Must have a scheme to be a full URL
    if '://' not in url:
        return False

    try:
        from urllib.parse import urlparse, unquote

        # Extract scheme manually before parsing (urlparse lowercases it)
        scheme_end = url.find('://')
        if scheme_end > 0:
            raw_scheme = url[:scheme_end]
            if raw_scheme != raw_scheme.lower():
                return True

        # Parse the URL
        parsed = urlparse(url)

        # Extract hostname manually to check case (urlparse lowercases it)
        # Get netloc portion
        if '://' in url:
            after_scheme = url.split('://', 1)[1]
            # Split on first / ? or #
            netloc_end = len(after_scheme)
            for char in ['/', '?', '#']:
                pos = after_scheme.find(char)
                if pos != -1:
                    netloc_end = min(netloc_end, pos)
            raw_netloc = after_scheme[:netloc_end]

            # Extract host from netloc (remove userinfo and port)
            raw_host = raw_netloc
            if '@' in raw_host:
                raw_host = raw_host.split('@', 1)[1]
            if ':' in raw_host and not raw_host.startswith('['):
                raw_host = raw_host.split(':', 1)[0]
            elif raw_host.startswith('[') and ']:' in raw_host:
                raw_host = raw_host.split(']:')[0] + ']'

            # Check host case
            if raw_host and raw_host != raw_host.lower():
                return True

        # Check for trailing dot in hostname
        netloc = parsed.netloc
        if netloc:
            # Extract host portion (before port)
            host_part = netloc.split(':')[0] if ':' in netloc else netloc
            # Remove userinfo if present
            if '@' in host_part:
                host_part = host_part.split('@', 1)[1]
            # Check for trailing dot (except for root zone which is ok)
            if host_part.endswith('.') and host_part != '.':
                return True

        # Check for unnecessary default ports
        if parsed.port:
            scheme = parsed.scheme.lower()
            default_ports = {
                'http': 80,
                'https': 443,
                'ftp': 21,
                'ws': 80,
                'wss': 443,
            }
            if scheme in default_ports and parsed.port == default_ports[scheme]:
                return True

        # Check path normalization
        path = parsed.path
        if path:
            # Check for dot segments
            if '/./' in path or path.startswith('./'):
                return True
            if '/../' in path or path.startswith('../'):
                return True
            if path.endswith('/.') or path.endswith('/..'):
                return True

            # Check for unnecessary percent-encoding of unreserved characters
            # Unreserved chars: A-Z a-z 0-9 - . _ ~
            # These should never be percent-encoded
            import re
            unnecessary_encoded = re.findall(r'%([0-9A-Fa-f]{2})', path)
            for hex_val in unnecessary_encoded:
                char_code = int(hex_val, 16)
                # Check if it's an unreserved character
                char = chr(char_code)
                if char.isalnum() or char in '-._~':
                    return True

            # Check for mixed case in percent-encoding
            # All percent-encoded should be uppercase
            encoded_parts = re.findall(r'%[0-9A-Fa-f]{2}', path)
            for part in encoded_parts:
                if part != part.upper():
                    return True

        # Check query string
        query = parsed.query
        if query:
            # Check for mixed case in percent-encoding
            import re
            encoded_parts = re.findall(r'%[0-9A-Fa-f]{2}', query)
            for part in encoded_parts:
                if part != part.upper():
                    return True

        # Check for IPv6 non-canonical form (use raw_host to avoid parsing issues)
        if '://' in url:
            # Use the raw_host we extracted earlier
            if raw_host and raw_host.startswith('[') and ']' in raw_host:
                try:
                    import ipaddress
                    bracket_end = raw_host.index(']')
                    ipv6_str = raw_host[1:bracket_end]
                    # Remove zone ID if present
                    if '%' in ipv6_str:
                        ipv6_str = ipv6_str.split('%')[0]
                    # Parse and get canonical form
                    ipv6_obj = ipaddress.IPv6Address(ipv6_str)
                    canonical = str(ipv6_obj)
                    # Check if original matches canonical
                    if ipv6_str.lower() != canonical.lower():
                        return True
                except (ValueError, ipaddress.AddressValueError, NameError):
                    # Invalid IPv6 or raw_host not defined, that's a different validation issue
                    pass

        # Check fragment
        fragment = parsed.fragment
        if fragment:
            # Check for mixed case in percent-encoding
            import re
            encoded_parts = re.findall(r'%[0-9A-Fa-f]{2}', fragment)
            for part in encoded_parts:
                if part != part.upper():
                    return True

    except (ValueError, AttributeError):
        # If parsing fails, we can't determine canonicality
        return False

    return False


def get_canonical_url(url: str) -> Optional[str]:
    """Convert URL to canonical form.

    Produces a canonical representation of the URL by:
    - Lowercasing scheme and host
    - Removing default ports
    - Normalizing path (removing . and .. segments)
    - Removing trailing dots from hostname
    - Uppercasing percent-encoding
    - Converting IPv6 to canonical form

    Args:
        url: The URL to canonicalize

    Returns:
        Canonical URL string, or None if URL is invalid

    Examples:
        >>> get_canonical_url("HTTP://EXAMPLE.COM:80/path")
        'http://example.com/path'
        >>> get_canonical_url("http://example.com/a/../b")
        'http://example.com/b'
    """
    if not isinstance(url, str) or not url:
        return None

    # Check if it looks like a URL (has a scheme)
    if '://' not in url:
        return None

    try:
        from urllib.parse import urlparse, urlunparse, unquote, quote
        import re

        parsed = urlparse(url)

        # Canonicalize scheme (lowercase)
        scheme = parsed.scheme.lower() if parsed.scheme else ""

        # Canonicalize netloc
        netloc = parsed.netloc
        if netloc:
            # Parse netloc components
            userinfo = ""
            port = parsed.port

            # Extract userinfo if present
            if '@' in netloc:
                userinfo_part, netloc_without_userinfo = netloc.rsplit('@', 1)
                userinfo = userinfo_part + '@'
            else:
                netloc_without_userinfo = netloc

            # Extract host (handle IPv6 specially)
            if netloc_without_userinfo.startswith('['):
                # IPv6
                if ']:' in netloc_without_userinfo:
                    host = netloc_without_userinfo.split(']:')[0] + ']'
                elif netloc_without_userinfo.endswith(']'):
                    host = netloc_without_userinfo
                else:
                    # Malformed, use hostname
                    host = f"[{parsed.hostname}]" if parsed.hostname else ""
            else:
                # Regular hostname or IPv4
                host = parsed.hostname or ""
                if ':' in netloc_without_userinfo and not netloc_without_userinfo.startswith('['):
                    host = netloc_without_userinfo.split(':', 1)[0]

            # Lowercase host
            host = host.lower()

            # Remove trailing dot
            if host.endswith('.') and host != '.':
                host = host[:-1]

            # Canonicalize IPv6
            if host.startswith('[') and host.endswith(']'):
                try:
                    import ipaddress
                    ipv6_str = host[1:-1]
                    zone_id = ""
                    if '%' in ipv6_str:
                        ipv6_str, zone_id = ipv6_str.split('%', 1)
                        zone_id = '%' + zone_id
                    ipv6_obj = ipaddress.IPv6Address(ipv6_str)
                    host = f"[{ipv6_obj}{zone_id}]"
                except (ValueError, ipaddress.AddressValueError):
                    pass  # Keep original if invalid

            # Remove default port
            if port:
                default_ports = {
                    'http': 80, 'https': 443, 'ftp': 21,
                    'ws': 80, 'wss': 443,
                }
                if scheme in default_ports and port == default_ports[scheme]:
                    port = None

            # Reconstruct netloc
            if port:
                netloc = f"{userinfo}{host}:{port}"
            else:
                netloc = f"{userinfo}{host}"

        # Normalize path
        path = parsed.path
        if path:
            # Normalize dot segments
            from posixpath import normpath
            path = normpath(path)

            # Uppercase percent-encoding and remove unnecessary encoding
            def replace_percent(match):
                hex_val = match.group(1)
                char_code = int(hex_val, 16)
                char = chr(char_code)
                # Don't decode unreserved characters - they should stay decoded
                # Unreserved: A-Z a-z 0-9 - . _ ~
                if char.isalnum() or char in '-._~':
                    return char
                # Keep percent-encoding but uppercase
                return f"%{hex_val.upper()}"

            path = re.sub(r'%([0-9A-Fa-f]{2})', replace_percent, path)

        # Uppercase percent-encoding in query and fragment
        query = parsed.query
        if query:
            query = re.sub(
                r'%([0-9A-Fa-f]{2})',
                lambda m: f"%{m.group(1).upper()}",
                query
            )

        fragment = parsed.fragment
        if fragment:
            fragment = re.sub(
                r'%([0-9A-Fa-f]{2})',
                lambda m: f"%{m.group(1).upper()}",
                fragment
            )

        # Reconstruct URL
        canonical = urlunparse((scheme, netloc, path, parsed.params, query, fragment))
        return canonical

    except (ValueError, AttributeError):
        return None


def has_suspicious_punycode(host: str) -> bool:
    """Detect suspicious Punycode/IDN domains with confusable characters.

    Internationalized Domain Names (IDN) using Punycode encoding can be abused
    for phishing attacks via homograph attacks. This function detects:

    1. Mixed scripts in decoded IDN (e.g., Latin + Cyrillic)
    2. Confusable character combinations (e.g., 'rn' looks like 'm')
    3. Suspicious TLDs commonly used in phishing
    4. All-numeric domain names in non-ASCII
    5. Excessive use of dashes/hyphens (common in phishing)

    Args:
        host: The hostname to check (may be punycode-encoded or decoded)

    Returns:
        True if suspicious patterns are detected, False otherwise

    Examples:
        >>> has_suspicious_punycode("xn--pple-43d.com")  # аpple (Cyrillic 'а')
        True
        >>> has_suspicious_punycode("example.com")
        False
        >>> has_suspicious_punycode("раура1.com")  # paypal with Cyrillic
        True
    """
    if not isinstance(host, str) or not host:
        return False

    host_lower = host.lower()

    # Check if it's a punycode domain
    is_punycode = 'xn--' in host_lower

    # Decode punycode if present
    decoded_host = host_lower
    if is_punycode:
        try:
            # Decode each label separately
            labels = host_lower.split('.')
            decoded_labels = []
            for label in labels:
                if label.startswith('xn--'):
                    try:
                        decoded = label.encode('ascii').decode('idna')
                        decoded_labels.append(decoded)
                    except (UnicodeError, UnicodeDecodeError):
                        decoded_labels.append(label)
                else:
                    decoded_labels.append(label)
            decoded_host = '.'.join(decoded_labels)
        except (UnicodeError, UnicodeDecodeError, ValueError):
            # If decoding fails, it might be malformed
            return True

    # Check for mixed scripts (already implemented, but check decoded version)
    if has_mixed_scripts(decoded_host):
        return True

    # Extract TLD
    parts = decoded_host.split('.')
    if len(parts) < 2:
        return False

    tld = parts[-1]
    domain = parts[-2] if len(parts) >= 2 else ''

    # Suspicious TLDs commonly used in phishing
    # These are legitimate TLDs but frequently abused
    suspicious_tlds = {
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free domains
        'pw', 'top', 'work', 'click', 'link',  # Cheap domains
        'xyz', 'loan', 'win', 'bid', 'racing',
        'download', 'stream', 'science', 'accountant',
    }

    # If it's punycode with a suspicious TLD, flag it
    if is_punycode and tld in suspicious_tlds:
        return True

    # Check for confusable character combinations
    # These are character pairs that look very similar
    confusable_pairs = [
        ('rn', 'm'),  # rn looks like m
        ('vv', 'w'),  # vv looks like w
        ('cl', 'd'),  # cl looks like d in some fonts
        ('l1', 'l1'),  # l and 1 look similar
        ('0o', '0o'),  # 0 and o look similar
    ]

    # Check domain name (not TLD) for confusables
    for pair in confusable_pairs:
        if pair[0] in domain:
            # Check if it might be intentionally confusing
            # e.g., "paypa1" (using 1 instead of l)
            return True

    # Check for excessive hyphens (common in phishing)
    # Legitimate domains rarely have more than 2 hyphens
    if domain.count('-') > 2:
        return True

    # Check for suspicious patterns: mixing ASCII digits with non-ASCII letters
    has_digits = any(c.isdigit() for c in domain)
    has_non_ascii = False
    try:
        domain.encode('ascii')
    except (UnicodeEncodeError, UnicodeDecodeError):
        has_non_ascii = True

    if has_digits and has_non_ascii:
        # Common phishing pattern: раура1.com (mixing Cyrillic with digits)
        return True

    # Check for all-numeric domain in non-ASCII
    # This is highly suspicious
    if has_non_ascii:
        # Remove common punctuation
        domain_no_punct = domain.replace('-', '').replace('_', '')
        if domain_no_punct and all(c.isdigit() for c in domain_no_punct if c.isalnum()):
            return True

    # Check for known brand impersonation patterns
    # Common brands that are frequently targeted
    common_brands = [
        'paypal', 'google', 'amazon', 'apple', 'microsoft',
        'facebook', 'twitter', 'instagram', 'netflix', 'ebay',
        'bank', 'secure', 'login', 'account', 'verify',
    ]

    # If domain contains a brand name and non-ASCII, it's suspicious
    if has_non_ascii:
        for brand in common_brands:
            # Check if brand appears with possible character substitution
            # This is a simplified check
            if brand in decoded_host.lower():
                return True

    return False


def has_query_injection(query_string: str) -> bool:
    """Detect potential XSS/injection patterns in query strings.

    Query parameters are a common injection vector for various attacks:
    - Cross-Site Scripting (XSS): <script>, onerror=, javascript:
    - SQL Injection: UNION SELECT, OR 1=1, DROP TABLE
    - Command Injection: |, &&, ;, $(...)
    - LDAP Injection: *, )(, |
    - XML Injection: <!, CDATA, DOCTYPE

    This function detects common injection patterns but should NOT be used
    as the sole defense. Always use proper input validation, output encoding,
    and parameterized queries/prepared statements.

    Args:
        query_string: The query string portion of a URL (without leading ?)

    Returns:
        True if suspicious patterns are detected, False otherwise

    Examples:
        >>> has_query_injection("q=<script>alert(1)</script>")
        True
        >>> has_query_injection("name=John&age=25")
        False
        >>> has_query_injection("id=1' OR '1'='1")
        True
    """
    if not isinstance(query_string, str) or not query_string:
        return False

    # Normalize to lowercase for pattern matching
    query_lower = query_string.lower()

    # Also check a version with spaces normalized for patterns that might use whitespace
    # to evade detection (e.g., "UNION  SELECT" or "UNION%20SELECT")
    query_normalized = query_lower.replace('%20', ' ').replace('%09', ' ').replace('%0a', ' ')
    # Collapse multiple spaces
    while '  ' in query_normalized:
        query_normalized = query_normalized.replace('  ', ' ')

    # XSS patterns
    xss_patterns = [
        '<script', '</script', 'javascript:', 'onerror=', 'onload=',
        'onclick=', 'onmouseover=', '<iframe', '<object', '<embed',
        'vbscript:', 'data:text/html', '<img', 'src=', '<body',
        'onfocus=', 'onblur=', '<svg', 'onanimation', '<input',
    ]

    # SQL injection patterns
    sql_patterns = [
        'union select', 'union all select', "' or '", '" or "',
        "' or 1=1", '" or 1=1', "' and '", '" and "', "' and 1=1", '" and 1=1',
        'drop table', 'delete from', 'insert into', 'update set',
        '--', '/*', '*/', 'exec(', 'execute(', 'xp_cmdshell', 'sp_executesql',
        'sleep(', 'waitfor', 'benchmark(',
    ]

    # Command injection patterns
    cmd_patterns = [
        '$(', '`', '&&', '||', '; rm', ';rm ', ';cat ', '|cat', '|nc',
        '/bin/', '/etc/passwd', '/etc/shadow', 'cmd.exe', 'powershell',
    ]

    # LDAP injection patterns
    ldap_patterns = ['*)(', '(|', '(&', '(cn=*)']

    # XML/XXE patterns
    xml_patterns = ['<!entity', '<!doctype', '<![cdata[', '<?xml']

    # Path traversal in query (additional check)
    traversal_patterns = ['../', '..\\', '%2e%2e/', '%2e%2e\\', '%2e%2e%2f', '%2e%2e%5c']

    # Check all patterns in both original and normalized versions
    all_patterns = xss_patterns + sql_patterns + cmd_patterns + ldap_patterns + xml_patterns + traversal_patterns

    for pattern in all_patterns:
        if pattern in query_lower or pattern in query_normalized:
            return True

    # Check for encoded variations of dangerous characters
    # These might bypass simple filters but indicate potential injection
    encoded_patterns = [
        '%3c',  # <
        '%3e',  # >
        '%27',  # '
        '%22',  # "
        '%3b',  # ;
        '%7c',  # |
        '%26%26',  # &&
        '%7c%7c',  # ||
    ]

    for pattern in encoded_patterns:
        if pattern in query_lower:
            # Additional check: look for suspicious context
            # (e.g., %3cscript is suspicious, %3cvalue%3e might be legitimate)
            if pattern in ['%3c', '%3e']:  # < and >
                # Check if followed by common XSS keywords
                idx = query_lower.find(pattern)
                if idx != -1 and idx + len(pattern) < len(query_lower):
                    following = query_lower[idx + len(pattern):idx + len(pattern) + 10]
                    if any(kw in following for kw in ['script', 'iframe', 'object', 'svg', 'body', 'img']):
                        return True
            elif pattern in ['%27', '%22']:  # ' and "
                # Check for SQL-like patterns around quotes
                idx = query_lower.find(pattern)
                if idx != -1:
                    context = query_lower[max(0, idx - 10):min(len(query_lower), idx + 20)]
                    if any(kw in context for kw in ['or', 'and', 'union', 'select', '1=1']):
                        return True
            else:
                # Other encoded chars are suspicious enough on their own
                return True

    return False


def has_credentials(url: str) -> bool:
    """Detect URLs containing credentials (userinfo) in the authority component.

    URLs with embedded credentials pose security risks:
    - Credentials may be logged in plaintext
    - Browser history/cache exposure
    - Network logs and monitoring tools
    - Referrer header leakage
    - MITM attacks if transmitted over HTTP

    RFC 3986 allows userinfo (username:password@host) but it's deprecated
    for security reasons. Modern applications should use proper authentication
    mechanisms (OAuth, tokens, etc.) instead of embedding credentials in URLs.

    Args:
        url: The URL string to check

    Returns:
        True if credentials are detected, False otherwise

    Examples:
        >>> has_credentials("http://user:pass@example.com/path")
        True
        >>> has_credentials("http://example.com/path")
        False
        >>> has_credentials("ftp://admin@ftp.example.com")
        True
    """
    if not isinstance(url, str):
        return False

    # Must have a scheme to have authority component
    if '://' not in url:
        return False

    # Extract authority component (everything between :// and first / or end)
    after_scheme = url.split('://', 1)[1]

    # Split on first / to get authority
    if '/' in after_scheme:
        authority = after_scheme.split('/', 1)[0]
    else:
        authority = after_scheme.split('?', 1)[0].split('#', 1)[0]

    # Check for @ sign which indicates userinfo
    return '@' in authority


def extract_host_and_path(url: str) -> Tuple[str, str]:
    """Extract host and path portions from URL for security checks."""
    if '://' not in url:
        return "", ""
    after_scheme = url.split('://', 1)[1]
    if '/' in after_scheme:
        host_portion = after_scheme.split('/', 1)[0]
        path_portion = after_scheme[after_scheme.find('/'):]
    else:
        host_portion, path_portion = after_scheme, ""
    if '@' in host_portion:
        host_portion = host_portion.split('@', 1)[1]
    if ':' in host_portion and not host_portion.startswith('['):
        host_portion = host_portion.split(':', 1)[0]
    elif host_portion.startswith('[') and ']:' in host_portion:
        host_portion = host_portion.split(']:', 1)[0] + ']'
    if path_portion:
        path_portion = path_portion.split('?', 1)[0].split('#', 1)[0]
    return host_portion, path_portion


def is_dangerous_port(port: Optional[int], block_dangerous_ports: bool = False) -> bool:
    """Check if port is commonly exploited.

    Args:
        port: Port number to check
        block_dangerous_ports: If True, block ports in DANGEROUS_PORTS set

    Returns:
        True if port should be blocked, False otherwise
    """
    if not block_dangerous_ports or port is None:
        return False
    return port in DANGEROUS_PORTS


def normalize_url_unicode(url: str) -> str:
    """Normalize URL to NFC form to prevent normalization-based bypasses.

    This prevents "validate-then-normalize" vulnerabilities where attackers
    use Unicode tricks to bypass filters.
    """
    if not isinstance(url, str):
        return url
    try:
        return unicodedata.normalize('NFC', url)
    except (ValueError, TypeError):
        return url


def validate_url_security(url: str) -> None:
    """Run comprehensive security validations. Raises InvalidURLError if issue detected.

    Performance: Fast-path for pure ASCII URLs skips expensive Unicode checks.
    """
    from .exceptions import InvalidURLError

    url = normalize_url_unicode(url)

    is_ascii = True
    try:
        url.encode('ascii')
    except (UnicodeEncodeError, UnicodeDecodeError):
        is_ascii = False

    if has_double_encoding(url):
        raise InvalidURLError("URL contains double-encoded characters.")
    if '://' not in url:
        return
    host, path = extract_host_and_path(url)
    if host and is_malicious_ipv6_zone_id(host):
        raise InvalidURLError("IPv6 zone identifier contains invalid characters.")
    if host and not is_ascii and has_mixed_scripts(host):
        raise InvalidURLError("URL host contains mixed Unicode scripts.")
    if path:
        if has_path_traversal(path):
            raise InvalidURLError("URL path contains path traversal patterns.")
        if is_open_redirect_risk(path):
            raise InvalidURLError("URL path contains open redirect risk patterns.")
    if has_parser_confusion(url):
        raise InvalidURLError("URL contains ambiguous syntax that could cause parser confusion.")


_CACHED_FUNCTIONS = [is_private_ip, is_ssrf_risk, has_mixed_scripts]


def get_cache_info() -> dict:
    """Get statistics about security check caches."""
    return {f.__wrapped__.__name__: {'hits': f.cache_info().hits, 'misses': f.cache_info().misses,
                         'maxsize': f.cache_info().maxsize, 'currsize': f.cache_info().currsize}
            for f in _CACHED_FUNCTIONS if hasattr(f, 'cache_info')}


def clear_caches() -> dict:
    """Clear all security caches and return previous sizes."""
    previous = {f.__wrapped__.__name__: f.cache_info().currsize for f in _CACHED_FUNCTIONS if hasattr(f, 'cache_info')}
    for f in _CACHED_FUNCTIONS:
        if hasattr(f, 'cache_clear'):
            f.cache_clear()
    return previous


__all__ = [
    "is_ssrf_risk", "is_private_ip", "check_dns_rebinding", "has_mixed_scripts",
    "has_double_encoding", "has_path_traversal", "is_open_redirect_risk",
    "has_parser_confusion", "is_malicious_ipv6_zone_id", "normalize_url_unicode",
    "is_dangerous_port", "extract_host_and_path", "validate_url_security",
    "get_cache_info", "clear_caches",
    "check_against_phishing_db", "refresh_phishing_db", "get_phishing_db_info",
    "has_credentials", "has_query_injection", "has_suspicious_punycode",
    "DNSRateLimiter", "get_dns_rate_limiter", "reset_dns_rate_limiter", "check_dns_rate_limit",
    "is_non_canonical_url", "get_canonical_url",
]
