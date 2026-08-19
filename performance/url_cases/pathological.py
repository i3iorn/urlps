"""
Hand-written pathological URL corpus.

Deliberately contains ordinary absolute URLs, relative URLs, authority-less
URLs, credentials, ports, invalid ports, IPv4, IPv6, malformed IPv6, empty
components, fragments, query strings, enormous query strings, percent
encoding, Unicode, IDNs, whitespace, control characters, repeated
separators, dot segments, unusual schemes, file URLs, mailto/data URLs,
malformed URLs, and URLs designed to exercise lazy properties such as
urllib.parse.ParseResult.port.

Each section is tagged with its expected outcome (see EXPECTATION_* in
url_cases/_models.py) -- EXPECTATION_VALID for well-formed input,
EXPECTATION_INVALID for anything malformed under any reasonable
interpretation of the URI grammar (a raw control/whitespace character,
a non-digit port, a truncated/malformed IPv6 literal), and
EXPECTATION_AMBIGUOUS where reasonable spec-compliant parsers genuinely
disagree (out-of-range numeric ports, optional IPv6 zone-ID support,
unbracketed IPv6-shaped hosts). These are best-effort classifications,
not a formal grammar checker's output.
"""

from __future__ import annotations

from ._models import EXPECTATION_AMBIGUOUS, EXPECTATION_INVALID, EXPECTATION_VALID

#: (category, expected outcome, urls) -- flattened below into
#: PATHOLOGICAL_URLS/PATHOLOGICAL_EXPECTATIONS, kept structured here so each
#: URL's expectation stays next to the URL itself instead of drifting out
#: of sync in a separate parallel list.
_SECTIONS: list[tuple[str, str, list[str]]] = [
    (
        'Basic absolute URLs',
        EXPECTATION_VALID,
        [
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
        ],
    ),
    (
        'Schemes',
        EXPECTATION_VALID,
        [
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
        ],
    ),
    (
        'Paths',
        EXPECTATION_VALID,
        [
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
        ],
    ),
    (
        'Queries (valid, part 1)',
        EXPECTATION_VALID,
        [
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
        ],
    ),
    (
        'Queries (invalid)',
        EXPECTATION_INVALID,
        [
            "http://example.com/?q=%ZZ",
            "http://example.com/?q=%",
        ],
    ),
    (
        'Queries (valid, part 3)',
        EXPECTATION_VALID,
        [
            "http://example.com/?q=100%25",
        ],
    ),
    (
        'Fragments',
        EXPECTATION_VALID,
        [
            "http://example.com/#",
            "http://example.com/#top",
            "http://example.com/#section-1",
            "http://example.com/?a=1#top",
            "http://example.com/path#fragment",
        ],
    ),
    (
        'User info',
        EXPECTATION_VALID,
        [
            "http://user@example.com/",
            "http://admin@example.com/",
            "http://user:password@example.com/",
            "http://user:@example.com/",
            "http://:password@example.com/",
            "http://user%40name@example.com/",
            "http://user%3Apass@example.com/",
        ],
    ),
    (
        'Valid ports',
        EXPECTATION_VALID,
        [
            "http://example.com:1/",
            "http://example.com:80/",
            "http://example.com:443/",
            "http://example.com:8080/",
            "http://example.com:65535/",
        ],
    ),
    (
        "Invalid ports -- important for urllib's lazy .port property (valid, part 1)",
        EXPECTATION_VALID,
        [
            "http://example.com:0/",
        ],
    ),
    (
        "Invalid ports -- important for urllib's lazy .port property (invalid, part 2)",
        EXPECTATION_INVALID,
        [
            "http://example.com:-1/",
        ],
    ),
    (
        "Invalid ports -- important for urllib's lazy .port property (ambiguous, part 3)",
        EXPECTATION_AMBIGUOUS,
        [
            "http://example.com:65536/",
        ],
    ),
    (
        "Invalid ports -- important for urllib's lazy .port property (invalid, part 4)",
        EXPECTATION_INVALID,
        [
            "http://example.com:abc/",
        ],
    ),
    (
        "Invalid ports -- important for urllib's lazy .port property (ambiguous, part 5)",
        EXPECTATION_AMBIGUOUS,
        [
            "http://example.com:99999/",
        ],
    ),
    (
        "Invalid ports -- important for urllib's lazy .port property (valid, part 6)",
        EXPECTATION_VALID,
        [
            "http://example.com:/",
        ],
    ),
    (
        "Invalid ports -- important for urllib's lazy .port property (invalid, part 7)",
        EXPECTATION_INVALID,
        [
            "http://example.com:12abc/",
            "http://example.com:1.5/",
            "http://example.com:+80/",
            "http://example.com: 80/",
        ],
    ),
    (
        'IPv6 (valid, part 1)',
        EXPECTATION_VALID,
        [
            "http://[::1]/",
            "http://[::1]:80/",
            "http://[::1]:8080/path",
            "http://[2001:db8::1]/",
            "http://[2001:db8::1]:443/",
            "http://[fe80::1]/",
        ],
    ),
    (
        'IPv6 (ambiguous)',
        EXPECTATION_AMBIGUOUS,
        [
            "http://[fe80::1%25eth0]/",
        ],
    ),
    (
        'IPv6 (valid, part 3)',
        EXPECTATION_VALID,
        [
            "http://[::ffff:192.0.2.128]/",
        ],
    ),
    (
        'Malformed IPv6 (invalid, part 1)',
        EXPECTATION_INVALID,
        [
            "http://[]/",
            "http://[::/",
        ],
    ),
    (
        'Malformed IPv6 (ambiguous)',
        EXPECTATION_AMBIGUOUS,
        [
            "http://::1/",
        ],
    ),
    (
        'Malformed IPv6 (invalid, part 3)',
        EXPECTATION_INVALID,
        [
            "http://[1:2:3:4:5:6:7:8:9]/",
            "http://[gggg::1]/",
            "http://[::1",
            "http://::]/",
        ],
    ),
    (
        'Relative URLs',
        EXPECTATION_VALID,
        [
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
        ],
    ),
    (
        'Scheme-relative',
        EXPECTATION_VALID,
        [
            "//example.com",
            "//example.com/path",
            "//example.com:8080/path",
            "//user@example.com/path",
            "//[::1]/path",
        ],
    ),
    (
        'Unicode / IDN',
        EXPECTATION_VALID,
        [
            "https://例え.テスト/",
            "https://пример.рф/",
            "https://münich.example/",
            "https://example.com/café",
            "https://example.com/✓",
            "https://example.com/日本語",
            "https://example.com/?q=こんにちは",
            "https://example.com/#日本語",
        ],
    ),
    (
        'Whitespace',
        EXPECTATION_INVALID,
        [
            " http://example.com",
            "http://example.com ",
            " http://example.com ",
            "\thttp://example.com",
            "\nhttp://example.com",
            "http://example.com\n",
            "http://example.com\t",
        ],
    ),
    (
        'Control characters',
        EXPECTATION_INVALID,
        [
            "http://example.com/\x00",
            "http://example.com/\x01",
            "http://example.com/\x1f",
            "http://example.com/\x7f",
        ],
    ),
    (
        'Repeated / weird delimiters',
        EXPECTATION_VALID,
        [
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
        ],
    ),
    (
        'Host weirdness',
        EXPECTATION_VALID,
        [
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
        ],
    ),
    (
        'Long-ish URLs',
        EXPECTATION_VALID,
        [
            "https://example.com/" + "a" * 100,
            "https://example.com/" + "a" * 1000,
            "https://example.com/" + "a" * 10000,
        ],
    ),
    (
        'Query edge cases',
        EXPECTATION_VALID,
        [
            "https://example.com/?" + "a" * 1000,
            "https://example.com/?" + "a=1&" * 500,
        ],
    ),
]

PATHOLOGICAL_URLS: list[str] = [url for _, _, urls in _SECTIONS for url in urls]

PATHOLOGICAL_EXPECTATIONS: tuple[str, ...] = tuple(
    expectation for _, expectation, urls in _SECTIONS for _ in urls
)
