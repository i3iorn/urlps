"""One spelling of each host and port rule, shared by every layer.

The parser, the builder, the mutation path, the security checks and the
connect-time guard each used to carry their own copy of these, and the
copies drifted: one port check accepted any Unicode digit, one bracket
stripper kept the zone ID another dropped. A rule that decides what a host
*is* belongs here exactly once.

Bottom layer: imports nothing from the rest of the package, so anything
(including :mod:`urlps._security`) can use it without an import cycle. The
IDNA-aware ``canonical_host`` lives next to the IDNA encoder in
:mod:`urlps._unicode.uts46` for the same reason.
"""

from __future__ import annotations

__all__ = ["ip_literal_text", "is_ascii_digits", "looks_like_ipv4", "port_number", "strip_brackets"]

MIN_PORT = 1
MAX_PORT = 65535


def strip_brackets(host: str) -> str:
    """``"[::1]"`` -> ``"::1"``; anything not bracketed is returned unchanged."""
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def ip_literal_text(host: str) -> str:
    """The address text :mod:`ipaddress` and ``getaddrinfo`` expect.

    Brackets and an encoded zone ID (``%25eth0``) are removed:
    ``"[fe80::1%25eth0]"`` -> ``"fe80::1"``. Unbracketed input is returned
    unchanged.
    """
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1].partition("%25")[0]
    return host


def looks_like_ipv4(host: str) -> bool:
    """Whether ``host`` is shaped like a dotted IPv4 literal (and so must be a valid one).

    Digits, dots and hyphens only, with at least one dot: such a host is
    judged as an address, never as a hostname, so "1.2.3.999" is rejected
    rather than accepted as a name.
    """
    return "." in host and host.replace(".", "").replace("-", "").isdigit()


def is_ascii_digits(value: str) -> bool:
    """Non-empty and ASCII ``0-9`` only.

    ``str.isdigit()`` alone accepts every Unicode digit (fullwidth "22",
    U+FF12 U+FF12), which ``int()`` reads as 22 while other parsers reject
    it -- one port meaning two things to two parsers.
    """
    return bool(value) and value.isascii() and value.isdigit()


def port_number(value: object) -> int:
    """The one port grammar: an ``int`` (not ``bool``) or ASCII digits, in 1-65535.

    Raises:
        ValueError: ``value`` is not a port.
    """
    if isinstance(value, bool):
        raise ValueError("a bool is not a port")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and is_ascii_digits(value):
        number = int(value)
    else:
        raise ValueError(f"not a port number: {value!r}")
    if not MIN_PORT <= number <= MAX_PORT:
        raise ValueError(f"port out of range: {number}")
    return number
