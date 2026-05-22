"""Centralized regex patterns for URL parsing and validation.

All regex patterns used throughout the urlps library are defined here
for consistency and easier maintenance.
"""
from __future__ import annotations

import re
from typing import Dict, Pattern

PATTERNS: Dict[str, Pattern[str]] = {
    "scheme": re.compile(r"^[a-z][a-z0-9+\-.]{0,15}$"),

    "host": re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
        r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
    ),

    "ipv4": re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"),

    "ipv6": re.compile(r"^\[([0-9a-fA-F:]+)(%25[A-Za-z0-9_.~-]+)?\]$"),

    "url_safe_string": re.compile(r"^[A-Za-z0-9\-._~!$&'()*+,;=:@/%]*$"),

    "fragment": re.compile(
        r"^(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?\[\]]|%[0-9A-Fa-f]{2})*$"
    ),

    "control_chars": re.compile(r"[\s\x00-\x1F\x7F]"),

    "percent_encode": re.compile(r"%[0-9a-fA-F]{2}"),

    "double_encode": re.compile(r"%25[0-9A-Fa-f]{2}"),

    "userinfo": re.compile(r"^[^:@]+(?::[^@]*)?$"),
}


__all__ = ["PATTERNS"]
