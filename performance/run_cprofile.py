#!/usr/bin/env python3
"""Run cProfile over a batch of URLs using urlps.parse_url and produce aggregated stats.

Produces:
 - performance/profile_results.prof  (raw cProfile data)
 - performance/profile_results.txt   (human-readable top functions)

Usage:
    python performance/run_cprofile.py

The script generates ~100 URLs (mix of simple, complex, IPv6, long queries, relative)
and profiles parsing them repeatedly to surface hotspots.
"""
from __future__ import annotations

import sys
from pathlib import Path
import random
import time
import cProfile
import pstats

# Ensure src-layout package is importable for local runs
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from urlps import parse_url

OUTPUT_DIR = Path(__file__).parent
PROF_PATH = OUTPUT_DIR / "profile_results.prof"
TXT_PATH = OUTPUT_DIR / "profile_results.txt"


def generate_mixed_urls(n: int = 100, seed: int = 0) -> list[str]:
    random.seed(seed)
    urls = []
    hosts = ["example.com", "test.org", "sample.net", "localhost"]
    ipv6_hosts = ["[::1]", "[2001:db8::1]", "[fe80::1]"]
    simple_paths = ["/", "/index.html", "/api/data", "/path/to/resource"]
    queries = ["a=1&b=2", "x=foo&y=bar", "", '&'.join([f'p{i}=v{i}' for i in range(10)])]
    fragments = ["", "top", "section"]
    users = ["", "user", "admin"]
    ports = ["", "80", "443", "8080"]

    for i in range(n):
        choice = i % 6
        if choice == 0:
            # simple
            scheme = random.choice(["http", "https"])
            host = random.choice(hosts)
            path = random.choice(simple_paths)
            urls.append(f"{scheme}://{host}{path}")
        elif choice == 1:
            # complex
            scheme = random.choice(["http", "https"])
            user = random.choice(users)
            host = random.choice(hosts)
            port = random.choice(ports)
            path = random.choice(simple_paths)
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
        elif choice == 2:
            # ipv6
            host = random.choice(ipv6_hosts)
            urls.append(f"http://{host}/path?{random.choice(queries)}")
        elif choice == 3:
            # long query
            long_q = '&'.join([f'param{i}=value{i}' for i in range(40)])
            urls.append(f"https://example.com/search?{long_q}")
        elif choice == 4:
            # special encoded
            urls.append("https://example.com/search?q=hello%20world&special=%3D")
        else:
            # relative
            urls.append(random.choice(["/a/b/c", "../up/one", "resource.html", "./here"]))

    return urls


def profile_parsing(urls: list[str], repeats: int = 20) -> None:
    """Profile parse_url over the provided URLs repeated `repeats` times."""
    profiler = cProfile.Profile()
    total_parses = 0
    start_wall = time.perf_counter()
    profiler.enable()
    try:
        for _ in range(repeats):
            for u in urls:
                try:
                    parse_url(u)
                except Exception:
                    # Ignore parse errors; they are not the focus here
                    pass
                total_parses += 1
    finally:
        profiler.disable()
    end_wall = time.perf_counter()

    # Dump raw stats
    profiler.dump_stats(str(PROF_PATH))

    # Produce readable top-N by cumulative time
    stats = pstats.Stats(profiler).sort_stats('cumulative')
    with open(TXT_PATH, 'w', encoding='utf-8') as fh:
        fh.write(f'Profile run: {total_parses} parses, repeats={repeats}\n')
        fh.write(f'Wall time: {end_wall - start_wall:.4f}s\n\n')
        fh.write('Top 50 by cumulative time:\n')
        stats.stream = fh
        stats.print_stats(50)

    print(f'Wrote raw profile: {PROF_PATH}')
    print(f'Wrote summary: {TXT_PATH}')


if __name__ == '__main__':
    urls = generate_mixed_urls(n=1000, seed=42)
    print(f'Generated {len(urls)} URLs to profile')
    profile_parsing(urls, repeats=25)

