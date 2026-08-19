from __future__ import annotations

from ._models import EXPECTATION_INVALID, EXPECTATION_VALID, MODIFY_OPERATIONS, URLDataset
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


def build_datasets(
    *,
    simple: int = 1000,
    complex_: int = 1000,
    edge: int = 1000,
    mixed: int = 1000,
    rand: int = 1000,
) -> list[URLDataset]:
    """
    Build all standard benchmark datasets.

    Most generators produce internally homogeneous output, so those
    datasets carry a single dataset-wide `expectation` (see EXPECTATION_*
    in _models.py). `mixed` and `random-strings` deliberately blend
    valid/invalid/unparseable input and are left unannotated (unknown) --
    there's no single right answer to check a blended or purely random
    corpus against.
    """
    return [
        URLDataset(
            "simple",
            generate_simple_urls(simple, seed=0),
            expectation=EXPECTATION_VALID,
        ),
        URLDataset(
            "complex",
            generate_complex_urls(complex_, seed=1),
            expectation=EXPECTATION_VALID,
        ),
        URLDataset(
            "pathological",
            list(PATHOLOGICAL_URLS),
            skip_repeated_parse=True,
            per_url_expectations=PATHOLOGICAL_EXPECTATIONS,
        ),
        URLDataset(
            "malicious",
            list(MALICIOUS_URLS),
            excluded_operations=frozenset(MODIFY_OPERATIONS),
            skip_repeated_parse=True,
            per_url_expectations=MALICIOUS_EXPECTATIONS,
        ),
        URLDataset(
            "ipv6",
            generate_ipv6_urls(edge, seed=2),
            expectation=EXPECTATION_VALID,
        ),
        URLDataset(
            "invalid-port",
            generate_invalid_port_urls(edge, seed=3),
            expectation=EXPECTATION_INVALID,
        ),
        URLDataset(
            "long-query",
            generate_long_query_urls(max(1, edge // 2), seed=4),
            expectation=EXPECTATION_VALID,
        ),
        URLDataset(
            "encoded",
            generate_encoded_urls(edge, seed=5),
            expectation=EXPECTATION_VALID,
        ),
        URLDataset(
            "relative",
            generate_relative_urls(edge, seed=6),
            expectation=EXPECTATION_VALID,
        ),
        URLDataset(
            "mixed",
            generate_mixed_urls(mixed, seed=42),
        ),
        URLDataset(
            "random-strings",
            generate_random_strings(rand, seed=7),
        ),
    ]
