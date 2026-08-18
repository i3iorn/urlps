"""
URL corpus and generators for URL parser benchmarking.

The goal here is not merely to generate "normal" URLs. The corpus deliberately
contains:

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
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass


# ============================================================================
# Static pathological corpus
# ============================================================================

PATHOLOGICAL_URLS: list[str] = [
    # ---------------------------------------------------------------------
    # Basic absolute URLs
    # ---------------------------------------------------------------------
    "http://example.com",
    "https://example.com",
    "http://example.com/",
    "https://example.com/index.html",
    "http://localhost",
    "http://localhost/",
    "http://127.0.0.1",
    "http://127.0.0.1:80/",
    "https://8.8.8.8/",
    "http://192.168.1.1:8080/api",

    # ---------------------------------------------------------------------
    # Schemes
    # ---------------------------------------------------------------------
    "ftp://example.com/file.txt",
    "ftps://example.com/file.txt",
    "ws://example.com/socket",
    "wss://example.com/socket",
    "file:///etc/hosts",
    "file://localhost/etc/hosts",
    "file:///C:/Windows/System32/drivers/etc/hosts",
    "mailto:user@example.com",
    "mailto:test@example.com?subject=Hello",
    "urn:isbn:9780131103627",
    "data:text/plain,hello",
    "data:text/plain;base64,SGVsbG8=",
    "custom://example.com/resource",

    # ---------------------------------------------------------------------
    # Paths
    # ---------------------------------------------------------------------
    "http://example.com/",
    "http://example.com/a",
    "http://example.com/a/b/c",
    "http://example.com/a/b/c/",
    "http://example.com/.",
    "http://example.com/..",
    "http://example.com/./a/../b",
    "http://example.com//",
    "http://example.com///",
    "http://example.com////a////b",
    "http://example.com/path with spaces",
    "http://example.com/%20",
    "http://example.com/%2F",
    "http://example.com/%252F",
    "http://example.com/%00",
    "http://example.com/%FF",
    "http://example.com/a%2Fb%2Fc",

    # ---------------------------------------------------------------------
    # Queries
    # ---------------------------------------------------------------------
    "http://example.com/?a=1",
    "http://example.com/?a=1&b=2",
    "http://example.com/?a=",
    "http://example.com/?=value",
    "http://example.com/?=",
    "http://example.com/?a",
    "http://example.com/?&&&",
    "http://example.com/?a=1&&b=2",
    "http://example.com/?a=1&",
    "http://example.com/?&a=1",
    "http://example.com/?a=1;b=2",
    "http://example.com/?q=hello%20world",
    "http://example.com/?q=%E2%9C%93",
    "http://example.com/?q=%ZZ",
    "http://example.com/?q=%",
    "http://example.com/?q=100%25",

    # ---------------------------------------------------------------------
    # Fragments
    # ---------------------------------------------------------------------
    "http://example.com/#",
    "http://example.com/#top",
    "http://example.com/#section-1",
    "http://example.com/?a=1#top",
    "http://example.com/path#fragment",

    # ---------------------------------------------------------------------
    # User info
    # ---------------------------------------------------------------------
    "http://user@example.com/",
    "http://admin@example.com/",
    "http://user:password@example.com/",
    "http://user:@example.com/",
    "http://:password@example.com/",
    "http://user%40name@example.com/",
    "http://user%3Apass@example.com/",

    # ---------------------------------------------------------------------
    # Valid ports
    # ---------------------------------------------------------------------
    "http://example.com:1/",
    "http://example.com:80/",
    "http://example.com:443/",
    "http://example.com:8080/",
    "http://example.com:65535/",

    # ---------------------------------------------------------------------
    # Invalid ports -- important for urllib's lazy .port property
    # ---------------------------------------------------------------------
    "http://example.com:0/",
    "http://example.com:-1/",
    "http://example.com:65536/",
    "http://example.com:abc/",
    "http://example.com:99999/",
    "http://example.com:/",
    "http://example.com:12abc/",
    "http://example.com:1.5/",
    "http://example.com:+80/",
    "http://example.com: 80/",

    # ---------------------------------------------------------------------
    # IPv6
    # ---------------------------------------------------------------------
    "http://[::1]/",
    "http://[::1]:80/",
    "http://[::1]:8080/path",
    "http://[2001:db8::1]/",
    "http://[2001:db8::1]:443/",
    "http://[fe80::1]/",
    "http://[fe80::1%25eth0]/",
    "http://[::ffff:192.0.2.128]/",

    # ---------------------------------------------------------------------
    # Malformed IPv6
    # ---------------------------------------------------------------------
    "http://[]/",
    "http://[::/",
    "http://::1/",
    "http://[1:2:3:4:5:6:7:8:9]/",
    "http://[gggg::1]/",
    "http://[::1",
    "http://::]/",

    # ---------------------------------------------------------------------
    # Relative URLs
    # ---------------------------------------------------------------------
    "/",
    "/a",
    "/a/b/c",
    "../",
    "../a",
    "../../a/b",
    "./",
    "./a",
    "a",
    "a/b",
    "a/b?x=1",
    "a/b#fragment",
    "?query=1",
    "#fragment",
    "",
    "...",
    ".../",
    "..",
    ".",

    # ---------------------------------------------------------------------
    # Scheme-relative
    # ---------------------------------------------------------------------
    "//example.com",
    "//example.com/path",
    "//example.com:8080/path",
    "//user@example.com/path",
    "//[::1]/path",

    # ---------------------------------------------------------------------
    # Unicode / IDN
    # ---------------------------------------------------------------------
    "https://例え.テスト/",
    "https://пример.рф/",
    "https://münich.example/",
    "https://example.com/café",
    "https://example.com/✓",
    "https://example.com/日本語",
    "https://example.com/?q=こんにちは",
    "https://example.com/#日本語",

    # ---------------------------------------------------------------------
    # Whitespace
    # ---------------------------------------------------------------------
    " http://example.com",
    "http://example.com ",
    " http://example.com ",
    "\thttp://example.com",
    "\nhttp://example.com",
    "http://example.com\n",
    "http://example.com\t",

    # ---------------------------------------------------------------------
    # Control characters
    # ---------------------------------------------------------------------
    "http://example.com/\x00",
    "http://example.com/\x01",
    "http://example.com/\x1f",
    "http://example.com/\x7f",

    # ---------------------------------------------------------------------
    # Repeated / weird delimiters
    # ---------------------------------------------------------------------
    "http:///example.com",
    "http:////example.com",
    "http://example.com?",
    "http://example.com#",
    "http://example.com?#",
    "http://example.com?#fragment",
    "http://example.com?query#",
    "http://example.com???",
    "http://example.com###",
    "http://example.com/path??x=1",
    "http://example.com/path##fragment",

    # ---------------------------------------------------------------------
    # Host weirdness
    # ---------------------------------------------------------------------
    "http://.",
    "http://..",
    "http://...",
    "http://-",
    "http://_",
    "http://localhost.localdomain",
    "http://example..com",
    "http://.example.com",
    "http://example.com.",
    "http://EXAMPLE.COM/",
    "http://Example.Com/",
    "http://127.0.0.1.1/",

    # ---------------------------------------------------------------------
    # Long-ish URLs
    # ---------------------------------------------------------------------
    "https://example.com/" + "a" * 100,
    "https://example.com/" + "a" * 1000,
    "https://example.com/" + "a" * 10000,

    # ---------------------------------------------------------------------
    # Query edge cases
    # ---------------------------------------------------------------------
    "https://example.com/?" + "a" * 1000,
    "https://example.com/?" + "a=1&" * 500,
]


# ============================================================================
# Static malicious corpus
#
# Categories, one section each:
#
# - SSRF: loopback/private/link-local IPs, cloud metadata endpoints,
#   decimal/octal/hex-encoded IPs, IPv4-mapped IPv6, *.local/*.internal
# - Path traversal (raw, encoded, double-encoded, backslash variants)
# - Open redirect / protocol-relative smuggling
# - Credential smuggling (the "https://trusted.com@evil.com/" phishing shape)
# - Homograph / confusable-script and punycode spoofing
# - Double-encoding (filter-bypass via re-encoded percent sequences)
# - Parser confusion (ambiguous host boundaries different parsers would
#   disagree on)
# - Query/header injection (XSS payloads, CRLF/header injection)
# - Null-byte and control-character smuggling outside the path
# - Dangerous ports (plaintext protocols proxied through an HTTP fetcher)
# - Alternate schemes used for SSRF pivoting (gopher/dict/file exploiting a
#   fetcher that blindly follows any scheme)
# - Wildcard-DNS SSRF bypass services (resolve attacker-controlled IPs
#   through a "legitimate-looking" hostname -- undetectable without a live
#   DNS lookup, included so the corpus documents the gap rather than
#   silently having one)
# ============================================================================

MALICIOUS_URLS: list[str] = [
    # ---------------------------------------------------------------------
    # SSRF: loopback / private / link-local
    # ---------------------------------------------------------------------
    "http://localhost/admin",
    "http://127.0.0.1/admin",
    "http://127.0.0.1:22/",
    "http://0.0.0.0/",
    "http://[::1]/admin",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://172.31.255.255/",
    "http://192.168.0.1/",
    "http://192.168.1.1/",
    "http://169.254.1.1/",
    "http://[fe80::1]/",

    # ---------------------------------------------------------------------
    # SSRF: cloud metadata endpoints
    # ---------------------------------------------------------------------
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.goog/computeMetadata/v1/",
    "http://169.254.170.2/v2/credentials/",
    "http://kubernetes.default.svc.cluster.local/",

    # ---------------------------------------------------------------------
    # SSRF: obfuscated/encoded IPs (bypass naive string-based blocklists)
    # ---------------------------------------------------------------------
    "http://2130706433/",  # decimal for 127.0.0.1
    "http://017700000001/",  # octal for 127.0.0.1
    "http://0x7f000001/",  # hex for 127.0.0.1
    "http://0x7f.0x0.0x0.0x1/",  # per-octet hex
    "http://0177.0.0.1/",  # per-octet octal
    "http://127.1/",  # short-form inet_aton
    "http://127.0.1/",
    "http://[::ffff:127.0.0.1]/",  # IPv4-mapped IPv6
    "http://[::ffff:169.254.169.254]/",  # IPv4-mapped IPv6 metadata endpoint
    "http://[0:0:0:0:0:ffff:a9fe:a9fe]/",  # metadata endpoint, fully-expanded IPv6

    # ---------------------------------------------------------------------
    # SSRF: internal-only TLDs
    # ---------------------------------------------------------------------
    "http://service.local/",
    "http://internal.corp.internal/",
    "http://box.localhost/",

    # ---------------------------------------------------------------------
    # SSRF: wildcard-DNS bypass services
    #
    # These resolve attacker-controlled hostnames to arbitrary (often
    # internal) IPs via the hostname itself, e.g. 127.0.0.1.nip.io ->
    # 127.0.0.1. No static string check can catch this without a live DNS
    # lookup (see check_dns=True / DNS rebinding protection) -- included so
    # the corpus documents the gap rather than silently having one.
    # ---------------------------------------------------------------------
    "http://127.0.0.1.nip.io/",
    "http://10.0.0.1.nip.io/",
    "http://127.0.0.1.sslip.io/",
    "http://127.0.0.1.xip.io/",

    # ---------------------------------------------------------------------
    # Path traversal
    # ---------------------------------------------------------------------
    "https://example.com/../../etc/passwd",
    "https://example.com/a/../../../etc/passwd",
    "https://example.com/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "https://example.com/%2e%2e/%2e%2e/etc/passwd",
    "https://example.com/..%2f..%2fetc%2fpasswd",
    "https://example.com/%252e%252e%252fetc%252fpasswd",  # double-encoded
    "https://example.com/....//....//etc/passwd",
    "https://example.com/..\\..\\windows\\system32",
    "https://example.com/path/%00.jpg/../../etc/passwd",

    # ---------------------------------------------------------------------
    # Open redirect / protocol-relative smuggling
    # ---------------------------------------------------------------------
    "https://example.com//evil.com/",
    "https://example.com///evil.com/",
    "https://example.com/\\evil.com/",
    "https://example.com/redirect?url=//evil.com",
    "https://example.com/redirect?url=https://evil.com",
    "https://example.com/%5cevil.com",

    # ---------------------------------------------------------------------
    # Credential smuggling (the classic phishing URL shape: the browser's
    # "host" is the part after the last unescaped @, not the trusted-looking
    # prefix before it)
    # ---------------------------------------------------------------------
    "https://paypal.com@evil.com/",
    "https://accounts.google.com@evil.com/login",
    "https://www.bank.com:password@evil.com/",
    "https://evil.com%2523@trusted.com/",
    "https://trusted.com%40evil.com/",

    # ---------------------------------------------------------------------
    # Homograph / confusable-script and punycode spoofing
    # ---------------------------------------------------------------------
    "https://аpple.com/",  # Cyrillic 'а' (U+0430) in "apple"
    "https://gооgle.com/",  # Cyrillic 'о' (U+043E) x2 in "google"
    "https://xn--pple-43d.com/",  # punycode for the Cyrillic 'а' apple.com
    "https://xn--80ak6aa92e.com/",  # punycode homograph domain
    "https://xn--e1afmkfd.xn--p1ai/",  # example.рф in punycode, mixed with ascii-looking path
    "https://ebay.com.verify-account.evil.com/",  # subdomain-prefix spoofing (not a script attack, but the same phishing intent)

    # ---------------------------------------------------------------------
    # Double-encoding (filter-bypass via re-encoded percent sequences)
    # ---------------------------------------------------------------------
    "https://example.com/?redirect=%252e%252e%252f",
    "https://example.com/%25252e%25252e%25252f",
    "https://example.com/?next=http%253A%252F%252Fevil.com",

    # ---------------------------------------------------------------------
    # Parser confusion (different parsers disagree on host boundaries)
    # ---------------------------------------------------------------------
    "https://trusted.com\\@evil.com/",
    "https://trusted.com#@evil.com/",
    "https://trusted.com?@evil.com/",
    "https://evil.com\\trusted.com/",
    "https:evil.com",
    "https:/\\evil.com",
    "http://foo@evil.com@trusted.com/",

    # ---------------------------------------------------------------------
    # Query / header injection
    # ---------------------------------------------------------------------
    "https://example.com/?q=<script>alert(1)</script>",
    "https://example.com/?redirect=javascript:alert(document.cookie)",
    "https://example.com/?q=\" onmouseover=\"alert(1)",
    "https://example.com/?next=data:text/html,<script>alert(1)</script>",
    "https://example.com/%0d%0aSet-Cookie:%20session=evil",
    "https://example.com/?redirect=%0d%0aLocation:%20https://evil.com",
    "https://example.com/\r\nHost: evil.com",

    # ---------------------------------------------------------------------
    # Null-byte / control-character smuggling outside the path
    # ---------------------------------------------------------------------
    "https://example.com%00.evil.com/",
    "https://example.com/login\x00.php",
    "https://evil.com\x00.trusted.com/",

    # ---------------------------------------------------------------------
    # Dangerous ports (plaintext/internal protocols behind an HTTP fetcher)
    # ---------------------------------------------------------------------
    "http://example.com:22/",
    "http://example.com:25/",
    "http://example.com:3306/",
    "http://example.com:6379/",
    "http://example.com:11211/",
    "http://example.com:27017/",

    # ---------------------------------------------------------------------
    # Alternate schemes for SSRF pivoting (classic Redis/Gopher exploit
    # shape: an HTTP client that blindly follows any scheme lets an
    # attacker speak an arbitrary internal protocol via a crafted "URL")
    # ---------------------------------------------------------------------
    "gopher://127.0.0.1:6379/_SET%20key%20value",
    "dict://127.0.0.1:11211/stat",
    "file:///etc/passwd",
    "file://127.0.0.1/etc/passwd",
    "ftp://127.0.0.1:21/",

    # ---------------------------------------------------------------------
    # IPv6 zone ID abuse
    # ---------------------------------------------------------------------
    "http://[fe80::1%25eth0]/",
    "http://[fe80::1%2500]/",
    "http://[fe80::1%25../../etc/passwd]/",
]


# ============================================================================
# Dataclass
# ============================================================================

@dataclass(frozen=True)
class URLDataset:
    name: str
    urls: list[str]

    @property
    def size(self) -> int:
        return len(self.urls)


# ============================================================================
# Helpers
# ============================================================================

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
    n: int = 5000,
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
    n: int = 5000,
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


def build_datasets(
    *,
    simple: int = 1000,
    complex_: int = 1000,
    edge: int = 1000,
    mixed: int = 5000,
) -> list[URLDataset]:
    """
    Build all standard benchmark datasets.
    """
    return [
        URLDataset(
            "simple",
            generate_simple_urls(simple, seed=0),
        ),
        URLDataset(
            "complex",
            generate_complex_urls(complex_, seed=1),
        ),
        URLDataset(
            "pathological",
            list(PATHOLOGICAL_URLS),
        ),
        URLDataset(
            "malicious",
            list(MALICIOUS_URLS),
        ),
        URLDataset(
            "ipv6",
            generate_ipv6_urls(edge, seed=2),
        ),
        URLDataset(
            "invalid-port",
            generate_invalid_port_urls(edge, seed=3),
        ),
        URLDataset(
            "long-query",
            generate_long_query_urls(max(1, edge // 2), seed=4),
        ),
        URLDataset(
            "encoded",
            generate_encoded_urls(edge, seed=5),
        ),
        URLDataset(
            "relative",
            generate_relative_urls(edge, seed=6),
        ),
        URLDataset(
            "mixed",
            generate_mixed_urls(mixed, seed=42),
        ),
        URLDataset(
            "random-strings",
            generate_random_strings(seed=7)
        )
    ]
