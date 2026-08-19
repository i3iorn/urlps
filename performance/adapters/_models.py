from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

#: Category tags a ParserAdapter can carry (see ParserAdapter.tags). Not an
#: enum -- adapters commonly need more than one (rfc3987 is both a parser
#: and a validator) -- but this is the vocabulary the CLI's --categories
#: filter and this docstring both assume:
#:
#:   parser          full parse -> components/query/reconstruct object model
#:   rfc3986         follows the RFC 3986 generic URI grammar
#:   whatwg          follows the WHATWG URL Living Standard (browser parsing)
#:   validation      answers "is this a well-formed/acceptable URL"
#:   normalization   canonicalizes a URL string
#:   security        SSRF/XSS/attack-surface-focused analysis
#:   http-client     URL handling that's a side effect of an HTTP client lib
#:   stdlib          ships in the Python standard library
#:   network         performs real I/O (DNS/HTTP) per call -- timings aren't
#:                   comparable to the purely-computational adapters and
#:                   results depend on network access being available. Only
#:                   included when named explicitly via --parser or
#:                   --categories network; never in the default selection.


@dataclass
class OperationError:
    """
    Error encountered while performing a parser operation.

    Errors are deliberately represented as data so that one malformed URL
    cannot terminate an entire benchmark run.
    """

    stage: str
    exception_type: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "stage": self.stage,
            "exception_type": self.exception_type,
            "message": self.message,
        }


@dataclass
class ComponentResult:
    """
    Result of extracting normalized/common URL components.
    """

    values: dict[str, Any] = field(default_factory=dict)
    errors: list[OperationError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass
class QueryResult:
    """
    Result of query extraction.
    """

    value: Any = None
    error: OperationError | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class ValidateResult:
    """
    Result of the `validate` operation, for adapters that judge a URL
    valid/invalid without producing a reusable parsed object (validators,
    urlpolice, url-jail, ...).

    `valid=False` with `error.exception_type == "Invalid"` means the
    validator *correctly ran* and judged the URL invalid -- that's the
    normal, expected way most of these libraries report rejection (they
    return a falsy verdict rather than raising). It is still recorded as a
    benchmark failure, same as a parser raising on malformed input: both
    represent "this URL did not produce a usable positive result." A real
    bug in the validator (an unexpected exception) is captured with its own
    real exception_type instead, so the two stay distinguishable in the
    error breakdown.
    """

    valid: bool = False
    error: OperationError | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class NormalizeResult:
    """
    Result of the `normalize` operation, for adapters that canonicalize a
    URL string (url-normalize) rather than parse it into components.
    """

    value: str | None = None
    error: OperationError | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def capture_error(stage: str, exc: BaseException) -> OperationError:
    """
    Convert an exception into a serializable benchmark error.
    """

    return OperationError(
        stage=stage,
        exception_type=type(exc).__name__,
        message=str(exc),
    )


def safe_call(
    fn: Callable[[], Any],
    *,
    stage: str,
) -> tuple[Any, OperationError | None]:
    """
    Safely invoke a callable.
    """

    try:
        return fn(), None
    except Exception as exc:
        return None, capture_error(stage, exc)


#: Fixed replacement values used by the modify_* benchmarks, so every parser
#: is exercised against the same mutation regardless of adapter.
MODIFIED_PATH = "/modified/path/segment"
MODIFIED_QUERY = "modified=1&extra=2"
MODIFIED_HOST = "modified.example.org"
MODIFIED_FRAGMENT = "modified-fragment"


#: operation name -> the ParserAdapter field that must be non-None for that
#: operation to be meaningful for a given adapter. Drives both
#: ParserAdapter.supported_operations and run_suite()'s per-adapter
#: operation filtering -- there is deliberately no separate "which ops does
#: this adapter support" list to keep in sync by hand; it's always derived
#: from what the adapter actually wired up.
OPERATION_REQUIREMENTS: dict[str, str] = {
    "parse": "parse",
    "components": "component_extractor",
    "query": "query_extractor",
    "reconstruct": "reconstructor",
    "modify_path": "path_modifier",
    "modify_query": "query_modifier",
    "modify_host": "host_modifier",
    "modify_fragment": "fragment_modifier",
    "validate": "validator",
    "normalize": "normalizer",
}


@dataclass
class ParserAdapter:
    """
    Generic adapter for a URL parser -- or a validator, normalizer, or
    security scanner; not every adapter is a full "parse into components"
    library (see `tags`).

    Required:
        name

    Optional (an adapter needs at least one of `parse`/`validator`/
    `normalizer` to do anything benchmarkable; see OPERATION_REQUIREMENTS
    and `supported_operations`):
        parse
        components / query / reconstruct
        path_modifier / query_modifier / host_modifier / fragment_modifier
        validator / normalizer
    """

    name: str

    #: Category tags, e.g. {"parser", "rfc3986"} or {"validation",
    #: "security"} -- see the module-level vocabulary comment above.
    #: Free-form on purpose: an adapter commonly needs more than one.
    tags: frozenset[str] = field(default_factory=frozenset)

    # None for adapters with no reusable "parsed object" step at all
    # (validators.url(), urlpolice's regex checks, url_normalize) -- those
    # rely on `validator`/`normalizer` instead, which operate directly on
    # the URL string. Every other operation below assumes a `parsed` object
    # produced by this, so an adapter offering components/query/reconstruct/
    # modify_* must set it.
    parse: Callable[[str], Any] | None = None

    component_extractor: Callable[[Any], ComponentResult] | None = None
    query_extractor: Callable[[Any], QueryResult] | None = None
    reconstructor: Callable[[Any], Any] | None = None

    # Each modifier takes the parsed object and returns a new object with
    # that single component replaced (with MODIFIED_PATH/QUERY/HOST/
    # FRAGMENT above), exercising each parser's "with_*"/copy-with-change
    # API rather than just parse+read.
    path_modifier: Callable[[Any], Any] | None = None
    query_modifier: Callable[[Any], Any] | None = None
    host_modifier: Callable[[Any], Any] | None = None
    fragment_modifier: Callable[[Any], Any] | None = None

    # `validate`/`normalize` operate on the raw URL string directly rather
    # than a parsed object -- most validation-only libraries (validators,
    # urlpolice) have no intermediate parsed representation at all, so
    # forcing them through a fake pass-through `parse` just to reach a
    # validator would misrepresent them as parsers.
    validator: Callable[[str], bool] | None = None
    normalizer: Callable[[str], str] | None = None

    description: str = ""

    available: bool = True
    unavailable_reason: str | None = None

    # Optional introspection hook returning that parser's internal cache
    # stats (hits/misses/maxsize/currsize per named cache), if it exposes
    # one. urlps does via get_cache_info(); most other parsers have no such
    # concept and leave this None.
    cache_info: Callable[[], dict[str, Any]] | None = None

    @property
    def supported_operations(self) -> frozenset[str]:
        """
        Which benchmark operations are meaningful for this adapter, derived
        from which of its extractor/modifier/validator fields are actually
        set -- see OPERATION_REQUIREMENTS. run_suite() uses this to skip
        the rest instead of recording a wall of NotSupportedError entries
        for e.g. running "components" against a pure validator.
        """
        return frozenset(
            operation
            for operation, field_name in OPERATION_REQUIREMENTS.items()
            if getattr(self, field_name) is not None
        )

    def components(self, parsed: Any) -> ComponentResult:
        if self.component_extractor is None:
            return ComponentResult(
                errors=[
                    OperationError(
                        stage="components",
                        exception_type="NotSupportedError",
                        message="Component extraction is not supported",
                    )
                ]
            )

        try:
            return self.component_extractor(parsed)
        except Exception as exc:
            return ComponentResult(
                errors=[capture_error("components", exc)]
            )

    def query(self, parsed: Any) -> QueryResult:
        if self.query_extractor is None:
            return QueryResult(
                error=OperationError(
                    stage="query",
                    exception_type="NotSupportedError",
                    message="Query extraction is not supported",
                )
            )

        try:
            return self.query_extractor(parsed)
        except Exception as exc:
            return QueryResult(
                error=capture_error("query", exc)
            )

    def reconstruct(
        self,
        parsed: Any,
    ) -> tuple[Any, OperationError | None]:
        if self.reconstructor is None:
            return None, OperationError(
                stage="reconstruct",
                exception_type="NotSupportedError",
                message="URL reconstruction is not supported",
            )

        return safe_call(
            lambda: self.reconstructor(parsed),
            stage="reconstruct",
        )

    def modify(
        self,
        parsed: Any,
        component: str,
    ) -> tuple[Any, OperationError | None]:
        """
        Apply the modify_<component> mutation (path/query/host/fragment).
        """

        modifier = {
            "path": self.path_modifier,
            "query": self.query_modifier,
            "host": self.host_modifier,
            "fragment": self.fragment_modifier,
        }.get(component)

        if modifier is None:
            return None, OperationError(
                stage=f"modify_{component}",
                exception_type="NotSupportedError",
                message=f"modify_{component} is not supported",
            )

        return safe_call(
            lambda: modifier(parsed),
            stage=f"modify_{component}",
        )

    def validate(self, url: str) -> ValidateResult:
        """
        Run the `validate` operation on a raw URL string (not a parsed
        object -- see `validator`'s docstring above).
        """
        if self.validator is None:
            return ValidateResult(
                error=OperationError(
                    stage="validate",
                    exception_type="NotSupportedError",
                    message="validate is not supported",
                )
            )

        try:
            if self.validator(url):
                return ValidateResult(valid=True)

            return ValidateResult(
                valid=False,
                error=OperationError(
                    stage="validate",
                    exception_type="Invalid",
                    message="URL judged invalid",
                ),
            )
        except Exception as exc:
            return ValidateResult(error=capture_error("validate", exc))

    def normalize(self, url: str) -> NormalizeResult:
        """
        Run the `normalize` operation on a raw URL string.
        """
        if self.normalizer is None:
            return NormalizeResult(
                error=OperationError(
                    stage="normalize",
                    exception_type="NotSupportedError",
                    message="normalize is not supported",
                )
            )

        try:
            return NormalizeResult(value=self.normalizer(url))
        except Exception as exc:
            return NormalizeResult(error=capture_error("normalize", exc))
