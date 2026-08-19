from __future__ import annotations

from performance.adapters._core import (
    URL_NORMALIZE_AVAILABLE,
    URL_NORMALIZE_IMPORT_ERROR,
)
from performance.adapters._core import url_normalize as _url_normalize_fn
from performance.adapters._models import ParserAdapter
from performance.adapters._registry import register_adapter


def _create_url_normalize_adapter() -> ParserAdapter:
    if not URL_NORMALIZE_AVAILABLE:
        reason = (
            "url-normalize is not installed"
            if URL_NORMALIZE_IMPORT_ERROR is None
            else f"url-normalize import failed: {URL_NORMALIZE_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="url-normalize",
            tags=frozenset({"normalization"}),
            normalizer=lambda url: url,
            description="url_normalize.url_normalize",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="url-normalize",
        tags=frozenset({"normalization"}),
        normalizer=_url_normalize_fn,
        description="url_normalize.url_normalize",
    )


url_normalize_adapter = _create_url_normalize_adapter()
register_adapter(url_normalize_adapter)
