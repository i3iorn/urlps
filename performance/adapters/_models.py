from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


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


@dataclass
class ParserAdapter:
    """
    Generic adapter for a URL parser.

    Required:
        name
        parse

    Optional:
        components
        query
        reconstruct
    """

    name: str
    parse: Callable[[str], Any]

    component_extractor: Callable[[Any], ComponentResult] | None = None
    query_extractor: Callable[[Any], QueryResult] | None = None
    reconstructor: Callable[[Any], Any] | None = None

    description: str = ""

    available: bool = True
    unavailable_reason: str | None = None

    # Optional introspection hook returning that parser's internal cache
    # stats (hits/misses/maxsize/currsize per named cache), if it exposes
    # one. urlps does via get_cache_info(); most other parsers have no such
    # concept and leave this None.
    cache_info: Callable[[], dict[str, Any]] | None = None

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
