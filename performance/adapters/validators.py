from __future__ import annotations

from performance.adapters._core import VALIDATORS_AVAILABLE, VALIDATORS_IMPORT_ERROR, validators_module
from performance.adapters._models import ParserAdapter
from performance.adapters._registry import register_adapter


def _validators_url_check(url: str) -> bool:
    """
    validators.url() doesn't raise for invalid input -- it returns True or
    a falsy ValidationError *object* (not a raised exception), so a plain
    bool() of the return value is exactly what ParserAdapter.validate()
    wants: True for valid, False for invalid, an exception only for a real
    bug in the library.
    """
    return bool(validators_module.url(url))


def _create_validators_adapter() -> ParserAdapter:
    if not VALIDATORS_AVAILABLE:
        reason = (
            "validators is not installed"
            if VALIDATORS_IMPORT_ERROR is None
            else f"validators import failed: {VALIDATORS_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="validators",
            tags=frozenset({"validation"}),
            validator=lambda _: False,
            description="validators.url",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="validators",
        tags=frozenset({"validation"}),
        validator=_validators_url_check,
        description="validators.url",
    )


validators_adapter = _create_validators_adapter()
register_adapter(validators_adapter)
