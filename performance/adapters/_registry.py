from typing import Any

from performance.adapters._models import ParserAdapter


# ============================================================================
# Registry
# ============================================================================

BUILTIN_ADAPTERS: dict[str, ParserAdapter] = {}

# ============================================================================
# Adapter registration
# ============================================================================

def register_adapter(adapter: ParserAdapter) -> None:
    """
    Register a custom parser.

    Example:

        register_adapter(
            ParserAdapter(
                name="myparser",
                parse=myparser.parse,
            )
        )
    """

    if not adapter.name:
        raise ValueError("Adapter name cannot be empty")

    BUILTIN_ADAPTERS[adapter.name] = adapter


def unregister_adapter(name: str) -> None:
    """
    Remove a registered adapter.

    This is useful for tests that want to temporarily modify the registry.
    """

    if name in BUILTIN_ADAPTERS:
        del BUILTIN_ADAPTERS[name]


# ============================================================================
# Adapter lookup
# ============================================================================

def get_adapter(name: str) -> ParserAdapter:
    """
    Retrieve a parser adapter by name.

    Raises:
        ValueError: if the parser is unknown.
    """

    try:
        return BUILTIN_ADAPTERS[name]

    except KeyError:
        available = ", ".join(sorted(BUILTIN_ADAPTERS))

        raise ValueError(
            f"Unknown parser {name!r}. Available parsers: {available}"
        )


def get_adapters(
    names: list[str] | None = None,
    *,
    available_only: bool = True,
) -> list[ParserAdapter]:
    """
    Return registered adapters.

    Args:
        names:
            Optional list of parser names. If omitted, all registered
            adapters are returned.

        available_only:
            If True, adapters whose optional dependencies are unavailable
            are excluded.

    Example:

        get_adapters()

        get_adapters(["urllib", "urlps", "yarl"])

        get_adapters(available_only=False)
    """

    if names is None:
        adapters = list(BUILTIN_ADAPTERS.values())
    else:
        adapters = [get_adapter(name) for name in names]

    if available_only:
        adapters = [
            adapter
            for adapter in adapters
            if adapter.available
        ]

    return adapters


# ============================================================================
# Availability helpers
# ============================================================================

def available_parser_names() -> list[str]:
    """
    Return names of currently available parsers.
    """

    return [
        adapter.name
        for adapter in BUILTIN_ADAPTERS.values()
        if adapter.available
    ]


def unavailable_parser_names() -> list[str]:
    """
    Return names of parsers whose optional dependencies are unavailable.
    """

    return [
        adapter.name
        for adapter in BUILTIN_ADAPTERS.values()
        if not adapter.available
    ]


def parser_availability() -> dict[str, dict[str, Any]]:
    """
    Return a machine-readable availability report.

    Example:

        {
            "urllib": {
                "available": True,
                "description": "...",
                "reason": None,
            },
            "yarl": {
                "available": False,
                "description": "...",
                "reason": "yarl is not installed",
            },
        }
    """

    return {
        adapter.name: {
            "available": adapter.available,
            "description": adapter.description,
            "reason": adapter.unavailable_reason,
        }
        for adapter in BUILTIN_ADAPTERS.values()
    }


def print_parser_availability() -> None:
    """
    Print parser availability in a human-friendly format.
    """

    print("Parser availability")
    print("=" * 72)

    for adapter in BUILTIN_ADAPTERS.values():
        status = "AVAILABLE" if adapter.available else "UNAVAILABLE"

        print(f"{adapter.name:<12} {status:<12} {adapter.description}")

        if not adapter.available and adapter.unavailable_reason:
            print(f"             {adapter.unavailable_reason}")

    print()
