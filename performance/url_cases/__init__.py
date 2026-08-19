"""
URL corpus and generators for URL parser benchmarking.

The goal here is not merely to generate "normal" URLs. Across the static
corpora (`pathological.py`, `malicious.py`) and the generators
(`generators.py`), the combined corpus deliberately contains:

- ordinary absolute URLs
- relative URLs
- authority-less URLs
- credentials
- ports
- invalid ports
- IPv4
- IPv6
- malformed IPv6
- empty components
- fragments
- query strings
- enormous query strings
- percent encoding
- Unicode
- IDNs
- whitespace
- control characters
- repeated separators
- dot segments
- unusual schemes
- file URLs
- mailto/data URLs
- malformed URLs
- URLs designed to exercise lazy properties such as urllib.parse.ParseResult.port
- random strings

This package re-exports everything callers need at the top level, so
`from performance.url_cases import ...` works exactly as it did when this
was a single module -- the split into pathological/malicious/generators/
datasets is an internal organization detail, not part of the public API.
"""

from __future__ import annotations

from ._models import (
    EXPECTATION_AMBIGUOUS,
    EXPECTATION_INVALID,
    EXPECTATION_UNKNOWN,
    EXPECTATION_UNSAFE,
    EXPECTATION_VALID,
    EXPECTATIONS,
    MODIFY_OPERATIONS,
    URLDataset,
)
from .datasets import build_datasets
from .generators import (
    generate_complex_urls,
    generate_encoded_urls,
    generate_invalid_port_urls,
    generate_ipv6_urls,
    generate_long_query_urls,
    generate_mixed_urls,
    generate_random_strings,
    generate_relative_urls,
    generate_simple_urls,
)
from .malicious import MALICIOUS_EXPECTATIONS, MALICIOUS_URLS
from .pathological import PATHOLOGICAL_EXPECTATIONS, PATHOLOGICAL_URLS

__all__ = [
    "EXPECTATIONS",
    "EXPECTATION_AMBIGUOUS",
    "EXPECTATION_INVALID",
    "EXPECTATION_UNKNOWN",
    "EXPECTATION_UNSAFE",
    "EXPECTATION_VALID",
    "MALICIOUS_EXPECTATIONS",
    "MALICIOUS_URLS",
    "MODIFY_OPERATIONS",
    "PATHOLOGICAL_EXPECTATIONS",
    "PATHOLOGICAL_URLS",
    "URLDataset",
    "build_datasets",
    "generate_complex_urls",
    "generate_encoded_urls",
    "generate_invalid_port_urls",
    "generate_ipv6_urls",
    "generate_long_query_urls",
    "generate_mixed_urls",
    "generate_random_strings",
    "generate_relative_urls",
    "generate_simple_urls",
]
