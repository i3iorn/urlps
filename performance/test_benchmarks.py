"""
pytest-benchmark integration.

These are intentionally separate from the large manual benchmark suite.

Run:

    pytest performance/test_benchmarks.py -v --benchmark-only
"""

from __future__ import annotations

from .adapters import urllib_adapter, urlps_adapter
from .url_cases import (
    generate_complex_urls,
    generate_simple_urls,
    generate_mixed_urls,
    generate_invalid_port_urls,
    generate_long_query_urls,
)


# ============================================================================
# Datasets
# ============================================================================

SIMPLE = generate_simple_urls(
    n=1000,
    seed=0,
)

COMPLEX = generate_complex_urls(
    n=1000,
    seed=1,
)

MIXED = generate_mixed_urls(
    n=2000,
    seed=42,
)

INVALID_PORTS = generate_invalid_port_urls(
    n=500,
    seed=3,
)

LONG_QUERIES = generate_long_query_urls(
    n=250,
    seed=4,
)


# ============================================================================
# Generic benchmark helpers
# ============================================================================

def benchmark_parse(
    adapter,
    urls,
):
    for url in urls:
        try:
            adapter.parse(url)
        except Exception:
            pass


def benchmark_components(
    adapter,
    urls,
):
    for url in urls:
        try:
            parsed = adapter.parse(url)
        except Exception:
            continue

        try:
            adapter.components(parsed)
        except Exception:
            pass


def benchmark_query(
    adapter,
    urls,
):
    for url in urls:
        try:
            parsed = adapter.parse(url)
        except Exception:
            continue

        try:
            adapter.query(parsed)
        except Exception:
            pass


def benchmark_reconstruct(
    adapter,
    urls,
):
    for url in urls:
        try:
            parsed = adapter.parse(url)
        except Exception:
            continue

        try:
            adapter.reconstruct(parsed)
        except Exception:
            pass


# ============================================================================
# Parse benchmarks
# ============================================================================

def test_urllib_parse_simple(benchmark):
    benchmark(
        benchmark_parse,
        urllib_adapter,
        SIMPLE,
    )


def test_urlps_parse_simple(benchmark):
    benchmark(
        benchmark_parse,
        urlps_adapter,
        SIMPLE,
    )


def test_urllib_parse_complex(benchmark):
    benchmark(
        benchmark_parse,
        urllib_adapter,
        COMPLEX,
    )


def test_urlps_parse_complex(benchmark):
    benchmark(
        benchmark_parse,
        urlps_adapter,
        COMPLEX,
    )


def test_urllib_parse_mixed(benchmark):
    benchmark(
        benchmark_parse,
        urllib_adapter,
        MIXED,
    )


def test_urlps_parse_mixed(benchmark):
    benchmark(
        benchmark_parse,
        urlps_adapter,
        MIXED,
    )


# ============================================================================
# Component benchmarks
# ============================================================================

def test_urllib_components_simple(benchmark):
    benchmark(
        benchmark_components,
        urllib_adapter,
        SIMPLE,
    )


def test_urlps_components_simple(benchmark):
    benchmark(
        benchmark_components,
        urlps_adapter,
        SIMPLE,
    )


def test_urllib_components_invalid_ports(benchmark):
    benchmark(
        benchmark_components,
        urllib_adapter,
        INVALID_PORTS,
    )


def test_urlps_components_invalid_ports(benchmark):
    benchmark(
        benchmark_components,
        urlps_adapter,
        INVALID_PORTS,
    )


# ============================================================================
# Query benchmarks
# ============================================================================

def test_urllib_query(benchmark):
    benchmark(
        benchmark_query,
        urllib_adapter,
        LONG_QUERIES,
    )


def test_urlps_query(benchmark):
    benchmark(
        benchmark_query,
        urlps_adapter,
        LONG_QUERIES,
    )


# ============================================================================
# Reconstruction benchmarks
# ============================================================================

def test_urllib_reconstruct(benchmark):
    benchmark(
        benchmark_reconstruct,
        urllib_adapter,
        COMPLEX,
    )


def test_urlps_reconstruct(benchmark):
    benchmark(
        benchmark_reconstruct,
        urlps_adapter,
        COMPLEX,
    )
