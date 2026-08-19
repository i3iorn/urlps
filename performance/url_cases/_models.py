from __future__ import annotations

from dataclasses import dataclass, field

#: The four benchmark operations that mutate a component and rebuild the
#: URL. Shared here (rather than in benchmark_suite.py) so a dataset can
#: reference it in `excluded_operations` without an import cycle.
MODIFY_OPERATIONS = (
    "modify_path",
    "modify_query",
    "modify_host",
    "modify_fragment",
)


# ============================================================================
# Expected outcome vocabulary
#
# Every prior version of this suite only ever recorded *whether* a parser
# accepted or rejected a URL -- never whether that was the *right* answer.
# That made "rejection rate" on the malicious corpus a fuzzy proxy at best:
# most of that corpus (SSRF targets, homograph domains, credential
# smuggling, ...) is syntactically perfectly valid URLs with dangerous
# *semantics* -- a plain RFC parser accepting "http://169.254.169.254/" is
# correct behavior, not a bug. Only a security-focused validator is
# expected to flag it. These four labels let each URL carry its own
# expected outcome so results can be scored against something real instead
# of guessed at the dataset level.
# ============================================================================

#: Should be accepted -- ordinary well-formed input.
EXPECTATION_VALID = "valid"

#: Malformed under (essentially) any reasonable interpretation of the URI
#: grammar -- a raw control character, a non-digit port, a truncated IPv6
#: literal, etc. A correct parser should reject it.
EXPECTATION_INVALID = "invalid"

#: Syntactically valid, semantically dangerous (SSRF target, path
#: traversal, credential smuggling, homograph domain, ...). Accepting it is
#: *not* a parsing bug -- only adapters tagged "security" are expected to
#: flag/reject it; everything else is simply not scored against it.
EXPECTATION_UNSAFE = "unsafe"

#: Genuinely disputed among reasonable, spec-compliant parsers -- e.g.
#: WHATWG treats backslashes as slashes for special schemes while RFC 3986
#: doesn't recognize them at all; numeric ports beyond 65535 are valid
#: *DIGIT grammar but out of range for a real port; RFC 6874 IPv6 zone-ID
#: support is optional. Never scored either way.
EXPECTATION_AMBIGUOUS = "ambiguous"

#: No expectation data for this URL (the default). Most of the randomly
#: generated corpora fall here -- a purely random string has no reliable
#: "correct" verdict to check against.
EXPECTATION_UNKNOWN = "unknown"

#: Every value `expectation`/`per_url_expectations` may hold.
EXPECTATIONS = frozenset(
    {
        EXPECTATION_VALID,
        EXPECTATION_INVALID,
        EXPECTATION_UNSAFE,
        EXPECTATION_AMBIGUOUS,
        EXPECTATION_UNKNOWN,
    }
)


@dataclass(frozen=True)
class URLDataset:
    name: str
    urls: list[str]

    # Not every operation is informative on every dataset -- e.g. modifying
    # a component of a URL from the malicious/adversarial corpus tests
    # nothing about that corpus's purpose (whether the *original* URL gets
    # flagged), it's just the same modify() codepath already covered by
    # every other dataset. Skipped operations are still counted as
    # "supported" by the adapter; they're just not run *for this dataset*.
    excluded_operations: frozenset[str] = field(default_factory=frozenset)

    # The repeated-parse benchmark exists to characterize realistic
    # repeated-fetch throughput; it adds little for small, hand-curated
    # correctness corpora (malicious/pathological) beyond what the regular
    # per-operation timing already shows, at ~3x the cost.
    skip_repeated_parse: bool = False

    # A single expectation applied to every URL in this dataset (see the
    # EXPECTATION_* constants above) -- the common case for generated
    # datasets, which are internally homogeneous (e.g. every URL from
    # generate_invalid_port_urls() is EXPECTATION_INVALID).
    expectation: str | None = None

    # Per-URL override, same length/order as `urls` -- for hand-curated
    # corpora (malicious/pathological) that mix expectations within one
    # dataset. Takes precedence over `expectation` wherever set.
    per_url_expectations: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if self.per_url_expectations is not None and len(self.per_url_expectations) != len(self.urls):
            raise ValueError(
                f"{self.name!r}: per_url_expectations has {len(self.per_url_expectations)} entries "
                f"but there are {len(self.urls)} urls"
            )

    @property
    def size(self) -> int:
        return len(self.urls)

    @property
    def expectations(self) -> tuple[str, ...]:
        """One expectation per URL, aligned 1:1 with `.urls`."""
        if self.per_url_expectations is not None:
            return self.per_url_expectations

        return tuple((self.expectation or EXPECTATION_UNKNOWN) for _ in self.urls)
