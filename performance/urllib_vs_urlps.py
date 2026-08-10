"""
Performance comparison between urllib.parse and urlps for URL parsing tasks.

This module provides comprehensive benchmarks comparing:
- Simple URL parsing
- URLs with various component combinations
- Edge cases (IPv6, long queries, etc.)
- Component access patterns
"""

import sys
from pathlib import Path

# Add src directory to path so we can import urlps without installation
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import random
import time
from urllib.parse import urlparse, urlunparse
from urlps import parse_url
import pytest


# ============================================================================
# URL Generation Functions
# ============================================================================

def generate_simple_urls(n: int = 100, seed: int = 0) -> list[str]:
    """Generate simple, common-case URLs."""
    random.seed(seed)
    schemes = ['http', 'https', 'ftp']
    hosts = ['example.com', 'test.org', 'sample.net', 'localhost']
    paths = ['/path/to/resource', '/another/path', '/index.html', '/api/data']

    urls = []
    for _ in range(n):
        scheme = random.choice(schemes)
        host = random.choice(hosts)
        path = random.choice(paths)
        url = f"{scheme}://{host}{path}"
        urls.append(url)
    return urls


def generate_complex_urls(n: int = 100, seed: int = 0) -> list[str]:
    """Generate URLs with all components (scheme, user, host, port, path, query, fragment)."""
    random.seed(seed)
    schemes = ['http', 'https', 'ftp']
    users = ['user', 'admin', 'test', '']
    hosts = ['example.com', 'test.org', 'sample.net', 'localhost']
    ports = ['80', '443', '8080', '3000', '']
    paths = ['/path/to/resource', '/another/path', '/index.html', '/api/data', '/']
    queries = ['a=1&b=2&c=3', 'x=foo&y=bar&z=baz', 'search=test&limit=10', 'id=123', '']
    fragments = ['section1', 'top', 'footer', 'reference', '']

    urls = []
    for _ in range(n):
        scheme = random.choice(schemes)
        user = random.choice(users)
        host = random.choice(hosts)
        port = random.choice(ports)
        path = random.choice(paths)
        query = random.choice(queries)
        fragment = random.choice(fragments)

        url = f"{scheme}://"
        if user:
            url += f"{user}@"
        url += host
        if port:
            url += f":{port}"
        url += path
        if query:
            url += f"?{query}"
        if fragment:
            url += f"#{fragment}"
        urls.append(url)
    return urls


def generate_edge_case_urls(n: int = 100, seed: int = 0) -> list[str]:
    """Generate edge case URLs: IPv6, special chars, long queries, etc."""
    random.seed(seed)
    urls = []

    # IPv6 addresses
    ipv6_hosts = ['[::1]', '[2001:db8::1]', '[fe80::1]']
    # Long query strings
    long_query = '&'.join([f'param{i}=value{i}' for i in range(20)])

    # Relative URLs
    relative_urls = ['/path/to/resource', '../parent/path', './current/path', 'resource.html']

    for i in range(n):
        choice = i % 4
        if choice == 0:
            # IPv6
            host = random.choice(ipv6_hosts)
            urls.append(f"http://{host}/path")
        elif choice == 1:
            # Long query
            urls.append(f"https://example.com/search?{long_query}")
        elif choice == 2:
            # Special characters (pick safe subset)
            base_query = 'q=hello%20world&special=%3D'
            urls.append(f"https://example.com/search?{base_query}")
        else:
            # Relative
            urls.append(random.choice(relative_urls))

    return urls


def generate_random_urls(n: int = 100, seed: int = 0) -> list[str]:
    """Generate mixed random URLs."""
    random.seed(seed)
    schemes = ['http', 'https', 'ftp', 'file']
    hosts = ['example.com', 'test.org', 'sample.net', 'localhost']
    paths = ['/path/to/resource', '/another/path', '/index.html', '/api/data']
    queries = ['a=1&b=2', 'x=foo&y=bar', 'search=test', '']
    fragments = ['section1', 'top', '', 'footer']

    urls = []
    for _ in range(n):
        scheme = random.choice(schemes)
        host = random.choice(hosts)
        path = random.choice(paths)
        query = random.choice(queries)
        fragment = random.choice(fragments)
        url = f"{scheme}://{host}{path}"
        if query:
            url += f"?{query}"
        if fragment:
            url += f"#{fragment}"
        urls.append(url)
    return urls


# ============================================================================
# Parsing Functions
# ============================================================================

def parse_with_urllib(urls: list[str]) -> None:
    """Parse all URLs using urllib.parse.urlparse."""
    for u in urls:
        _ = urlparse(u)


def parse_with_urlp(urls: list[str]) -> None:
    """Parse all URLs using urlps.parse_url."""
    for u in urls:
        try:
            _ = parse_url(u)
        except Exception:
            # Skip errors in edge cases for fair comparison
            pass


def access_components_urllib(urls: list[str]) -> None:
    """Parse and access all components using urllib."""
    for u in urls:
        parsed = urlparse(u)
        _ = (parsed.scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)


def access_components_urlp(urls: list[str]) -> None:
    """Parse and access all components using urlps."""
    for u in urls:
        try:
            parsed = parse_url(u)
            _ = (parsed.scheme, parsed.host, parsed.path, parsed.query, parsed.fragment)
        except Exception:
            pass


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def simple_urls() -> list[str]:
    return generate_simple_urls(n=1000, seed=0)


@pytest.fixture(scope="module")
def complex_urls() -> list[str]:
    return generate_complex_urls(n=500, seed=1)


@pytest.fixture(scope="module")
def edge_case_urls() -> list[str]:
    return generate_edge_case_urls(n=500, seed=2)


@pytest.fixture(scope="module")
def random_urls() -> list[str]:
    return generate_random_urls(n=1000, seed=3)


# ============================================================================
# Additional Parsing Functions for Advanced Tests
# ============================================================================

def parse_repeated_urllib(urls: list[str], repeats: int = 3) -> None:
    """Parse the same URL multiple times using urllib."""
    for _ in range(repeats):
        for u in urls:
            _ = urlparse(u)


def parse_repeated_urlp(urls: list[str], repeats: int = 3) -> None:
    """Parse the same URL multiple times using urlps."""
    for _ in range(repeats):
        for u in urls:
            try:
                _ = parse_url(u)
            except Exception:
                pass


def extract_query_urllib(urls: list[str]) -> None:
    """Parse and extract query parameters using urllib."""
    from urllib.parse import parse_qs
    for u in urls:
        parsed = urlparse(u)
        if parsed.query:
            _ = parse_qs(parsed.query)


def extract_query_urlp(urls: list[str]) -> None:
    """Parse and extract query parameters using urlps."""
    for u in urls:
        try:
            parsed = parse_url(u)
            if parsed.query:
                # Just access query_pairs to trigger parsing
                _ = parsed.query_pairs
        except Exception:
            pass


def reconstruct_urllib(urls: list[str]) -> None:
    """Parse and reconstruct URLs using urllib."""
    for u in urls:
        parsed = urlparse(u)
        reconstructed = urlunparse(parsed)
        _ = reconstructed


def reconstruct_urlp(urls: list[str]) -> None:
    """Parse and reconstruct URLs using urlps."""
    for u in urls:
        try:
            parsed = parse_url(u)
            _ = str(parsed)
        except Exception:
            pass


# ============================================================================
# Benchmarks
# ============================================================================

def test_urllib_simple(benchmark, simple_urls):
    """Benchmark urllib on simple URLs."""
    benchmark.pedantic(parse_with_urllib, args=(simple_urls,), rounds=10, iterations=1)


def test_urlp_simple(benchmark, simple_urls):
    """Benchmark urlps on simple URLs."""
    benchmark.pedantic(parse_with_urlp, args=(simple_urls,), rounds=10, iterations=1)


def test_urllib_complex(benchmark, complex_urls):
    """Benchmark urllib on complex URLs."""
    benchmark.pedantic(parse_with_urllib, args=(complex_urls,), rounds=10, iterations=1)


def test_urlp_complex(benchmark, complex_urls):
    """Benchmark urlps on complex URLs."""
    benchmark.pedantic(parse_with_urlp, args=(complex_urls,), rounds=10, iterations=1)


def test_urllib_edge_cases(benchmark, edge_case_urls):
    """Benchmark urllib on edge case URLs."""
    benchmark.pedantic(parse_with_urllib, args=(edge_case_urls,), rounds=10, iterations=1)


def test_urlp_edge_cases(benchmark, edge_case_urls):
    """Benchmark urlps on edge case URLs."""
    benchmark.pedantic(parse_with_urlp, args=(edge_case_urls,), rounds=10, iterations=1)


def test_urllib_component_access(benchmark, random_urls):
    """Benchmark urllib on parsing + component access."""
    benchmark.pedantic(access_components_urllib, args=(random_urls,), rounds=10, iterations=1)


def test_urlp_component_access(benchmark, random_urls):
    """Benchmark urlps on parsing + component access."""
    benchmark.pedantic(access_components_urlp, args=(random_urls,), rounds=10, iterations=1)


def test_urllib_repeated(benchmark, simple_urls):
    """Benchmark urllib with repeated parsing."""
    benchmark.pedantic(parse_repeated_urllib, args=(simple_urls, 3), rounds=10, iterations=1)


def test_urlp_repeated(benchmark, simple_urls):
    """Benchmark urlps with repeated parsing."""
    benchmark.pedantic(parse_repeated_urlp, args=(simple_urls, 3), rounds=10, iterations=1)


def test_urllib_query_extraction(benchmark, complex_urls):
    """Benchmark urllib on query string extraction."""
    benchmark.pedantic(extract_query_urllib, args=(complex_urls,), rounds=10, iterations=1)


def test_urlp_query_extraction(benchmark, complex_urls):
    """Benchmark urlps on query string extraction."""
    benchmark.pedantic(extract_query_urlp, args=(complex_urls,), rounds=10, iterations=1)


def test_urllib_reconstruct(benchmark, random_urls):
    """Benchmark urllib on URL reconstruction."""
    benchmark.pedantic(reconstruct_urllib, args=(random_urls,), rounds=10, iterations=1)


def test_urlp_reconstruct(benchmark, random_urls):
    """Benchmark urlps on URL reconstruction."""
    benchmark.pedantic(reconstruct_urlp, args=(random_urls,), rounds=10, iterations=1)


# ============================================================================
# Manual Performance Analysis
# ============================================================================

def manual_performance_analysis() -> None:
    """Run manual performance tests and generate a detailed report."""
    print("\n" + "=" * 80)
    print("MANUAL PERFORMANCE ANALYSIS: urllib.parse vs urlps")
    print("=" * 80)

    # Prepare test datasets
    simple_urls = generate_simple_urls(n=1000, seed=0)
    complex_urls = generate_complex_urls(n=500, seed=1)
    edge_case_urls = generate_edge_case_urls(n=500, seed=2)

    test_cases = [
        ("Simple URLs (1000 items)", simple_urls, parse_with_urllib, parse_with_urlp),
        ("Complex URLs (500 items)", complex_urls, parse_with_urllib, parse_with_urlp),
        ("Edge Case URLs (500 items)", edge_case_urls, parse_with_urllib, parse_with_urlp),
        ("Component Access (1000 items)", simple_urls, access_components_urllib, access_components_urlp),
        ("Query Extraction (500 items)", complex_urls, extract_query_urllib, extract_query_urlp),
        ("URL Reconstruction (1000 items)", simple_urls, reconstruct_urllib, reconstruct_urlp),
    ]

    results = []

    for test_name, urls, urllib_func, urlp_func in test_cases:
        print(f"\n{test_name}")
        print("-" * 80)

        # Warmup runs
        for _ in range(2):
            urllib_func(urls)
            urlp_func(urls)

        # Time urllib
        start = time.perf_counter()
        for _ in range(5):
            urllib_func(urls)
        urllib_time = time.perf_counter() - start

        # Time urlps
        start = time.perf_counter()
        for _ in range(5):
            urlp_func(urls)
        urlp_time = time.perf_counter() - start

        ratio = urlp_time / urllib_time if urllib_time > 0 else float('inf')
        faster = "urllib" if urllib_time < urlp_time else "urlps"
        percent_diff = abs(urlp_time - urllib_time) / min(urllib_time, urlp_time) * 100

        print(f"  urllib time: {urllib_time*1000:.4f} ms")
        print(f"  urlps time:   {urlp_time*1000:.4f} ms")
        print(f"  Ratio (urlps/urllib): {ratio:.2f}x")
        print(f"  {faster} is {percent_diff:.1f}% faster")

        results.append({
            'test': test_name,
            'urllib_ms': urllib_time * 1000,
            'urlp_ms': urlp_time * 1000,
            'ratio': ratio,
        })

    # Summary table
    print("\n" + "=" * 80)
    print("SUMMARY TABLE")
    print("=" * 80)
    print(f"{'Test Case':<40} {'urllib (ms)':<15} {'urlps (ms)':<15} {'Ratio':<10}")
    print("-" * 80)
    for r in results:
        print(f"{r['test']:<40} {r['urllib_ms']:<15.4f} {r['urlp_ms']:<15.4f} {r['ratio']:<10.2f}x")

    avg_ratio = sum(r['ratio'] for r in results) / len(results)
    print("-" * 80)
    print(f"{'Average ratio:':<40} {'':<15} {'':<15} {avg_ratio:.2f}x")
    print("=" * 80 + "\n")


# ============================================================================
# Standalone Execution
# ============================================================================

if __name__ == "__main__":
    import sys

    if "--manual" in sys.argv:
        # Run manual performance analysis
        manual_performance_analysis()
    else:
        # Run pytest benchmarks
        import pytest as _pytest
        _pytest.main(["-v", "--benchmark-only"] + [arg for arg in sys.argv[1:] if arg != "--manual"])
