"""
Randomized URL generators for URL parser benchmarking.

Each generator is deterministic (seeded) so a given (n, seed) always
produces the same corpus, but between them cover: ordinary absolute URLs,
credentials, ports, invalid ports, IPv4, IPv6, empty components, enormous
query strings, percent encoding, relative URLs, and random strings for
raw parser stress-testing.
"""

from __future__ import annotations

import random
import string


def _random_token(rng: random.Random, length: int = 8) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def generate_simple_urls(
    n: int = 1000,
    seed: int = 0,
) -> list[str]:
    rng = random.Random(seed)

    schemes = ["http", "https", "ftp"]
    hosts = [
        "example.com",
        "test.org",
        "sample.net",
        "localhost",
        "127.0.0.1",
    ]
    paths = [
        "/",
        "/index.html",
        "/api/data",
        "/path/to/resource",
        "/another/path",
    ]

    return [
        f"{rng.choice(schemes)}://{rng.choice(hosts)}{rng.choice(paths)}"
        for _ in range(n)
    ]


def generate_complex_urls(
    n: int = 1000,
    seed: int = 1,
) -> list[str]:
    rng = random.Random(seed)

    schemes = ["http", "https", "ftp"]
    users = ["", "user", "admin", "test"]
    hosts = [
        "example.com",
        "test.org",
        "sample.net",
        "localhost",
    ]
    ports = ["", "80", "443", "8080", "3000"]
    paths = [
        "/",
        "/path/to/resource",
        "/another/path",
        "/index.html",
        "/api/data",
    ]
    queries = [
        "",
        "a=1&b=2",
        "x=foo&y=bar",
        "search=test&limit=10",
        "id=123",
        "q=hello%20world&special=%3D",
    ]
    fragments = ["", "top", "section1", "footer"]

    urls: list[str] = []

    for _ in range(n):
        scheme = rng.choice(schemes)
        user = rng.choice(users)
        host = rng.choice(hosts)
        port = rng.choice(ports)
        path = rng.choice(paths)
        query = rng.choice(queries)
        fragment = rng.choice(fragments)

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


def generate_ipv6_urls(
    n: int = 500,
    seed: int = 2,
) -> list[str]:
    rng = random.Random(seed)

    hosts = [
        "[::1]",
        "[2001:db8::1]",
        "[fe80::1]",
        "[::ffff:192.0.2.128]",
    ]
    ports = ["", ":80", ":443", ":8080"]
    paths = ["/", "/path", "/api/data", "/index.html"]

    return [
        f"https://{rng.choice(hosts)}{rng.choice(ports)}{rng.choice(paths)}"
        for _ in range(n)
    ]


def generate_invalid_port_urls(
    n: int = 500,
    seed: int = 3,
) -> list[str]:
    rng = random.Random(seed)

    ports = [
        "abc",
        "-1",
        "65536",
        "99999",
        "1.5",
        "+80",
        "12abc",
        " ",
        "\t",
        "999999999999999999999",
    ]

    return [
        f"http://{rng.choice(['example.com', 'localhost', '127.0.0.1'])}:{rng.choice(ports)}/"
        for _ in range(n)
    ]


def generate_long_query_urls(
    n: int = 250,
    seed: int = 4,
    parameters: int = 100,
) -> list[str]:
    rng = random.Random(seed)

    urls: list[str] = []

    for _ in range(n):
        count = rng.randint(max(1, parameters // 2), parameters)

        query = "&".join(
            f"{_random_token(rng, 8)}={_random_token(rng, 16)}"
            for _ in range(count)
        )

        urls.append(f"https://example.com/search?{query}")

    return urls


def generate_encoded_urls(
    n: int = 500,
    seed: int = 5,
) -> list[str]:
    rng = random.Random(seed)

    values = [
        "hello%20world",
        "%E2%9C%93",
        "%2F",
        "%3F",
        "%23",
        "%26",
        "%3D",
        "%25",
        "%00",
        "%FF",
        "%252F",
        "%252525",
    ]

    return [
        (
            "https://example.com/search"
            f"?q={rng.choice(values)}"
            f"&value={rng.choice(values)}"
        )
        for _ in range(n)
    ]


def generate_relative_urls(
    n: int = 500,
    seed: int = 6,
) -> list[str]:
    rng = random.Random(seed)

    candidates = [
        "/",
        "/a",
        "/a/b/c",
        "../",
        "../up",
        "../../up/two",
        "./here",
        "resource.html",
        "a/b/c",
        "?q=1",
        "#fragment",
        "a/b?q=1#x",
        "//example.com/path",
    ]

    return [rng.choice(candidates) for _ in range(n)]


def generate_mixed_urls(
    n: int = 1000,
    seed: int = 42,
) -> list[str]:
    """
    Generate a broad deterministic mixture.

    Unlike the original generator, this includes invalid inputs deliberately.
    """
    rng = random.Random(seed)

    pools = [
        generate_simple_urls(max(1, n // 10), seed + 1),
        generate_complex_urls(max(1, n // 10), seed + 2),
        generate_ipv6_urls(max(1, n // 10), seed + 3),
        generate_invalid_port_urls(max(1, n // 10), seed + 4),
        generate_long_query_urls(max(1, n // 10), seed + 5),
        generate_encoded_urls(max(1, n // 10), seed + 6),
        generate_relative_urls(max(1, n // 10), seed + 7),
    ]

    urls: list[str] = []

    while len(urls) < n:
        pool = rng.choice(pools)
        urls.append(rng.choice(pool))

    return urls[:n]


def generate_random_strings(
    n: int = 1000,
    seed: int = 7,
    min_len: int = 0,
    max_len: int = 5000,
) -> list[str]:
    """
    Generate deterministic random strings for parser stress testing.

    The generated corpus deliberately contains a mixture of:

    - empty strings
    - very short strings
    - normal-length strings
    - long strings
    - ASCII letters
    - digits
    - punctuation
    - URL-ish characters
    - whitespace
    - percent-encoding characters
    - Unicode characters

    The random seed makes the corpus reproducible.

    Args:
        n:
            Number of strings to generate.

        seed:
            Seed for deterministic generation.

        min_len:
            Minimum generated string length.

        max_len:
            Maximum generated string length.

    Returns:
        A list containing exactly ``n`` random strings.

    Raises:
        ValueError:
            If ``n`` is negative or ``min_len > max_len``.
    """
    if n < 0:
        raise ValueError("n must be >= 0")

    if min_len < 0:
        raise ValueError("min_len must be >= 0")

    if max_len < min_len:
        raise ValueError("max_len must be >= min_len")

    rng = random.Random(seed)

    ascii_chars = string.ascii_letters
    digits = string.digits

    punctuation = "!#$%&'()*+,-./:;=?@[]_~"
    whitespace = " \t\r\n"

    unicode_chars = (
        "é"
        "ö"
        "å"
        "ü"
        "ñ"
        "ø"
        "ß"
        "中"
        "文"
        "日"
        "本"
        "語"
        "😀"
        "🚀"
        "☃"
        "€"
        "£"
        "¥"
    )

    alphabet = (
        ascii_chars
        + digits
        + punctuation
        + whitespace
        + unicode_chars
    )

    strings: list[str] = []

    for _ in range(n):
        str_len = rng.randint(min_len, max_len)

        if str_len == 0:
            strings.append("")
            continue

        value = "".join(
            rng.choice(alphabet)
            for _ in range(str_len)
        )

        strings.append(value)

    return strings
