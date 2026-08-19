from __future__ import annotations

from typing import Any

from performance.adapters._core import REQUESTS_AVAILABLE, REQUESTS_IMPORT_ERROR, RequestsPreparedRequest
from performance.adapters._models import ParserAdapter
from performance.adapters._registry import register_adapter

# requests has no standalone URL-object model of its own -- under the hood
# PreparedRequest.prepare_url() delegates most of the real parsing to
# urllib3 (already covered by the `urllib3` adapter). What's specifically
# requests' own behavior, and worth benchmarking separately, is the
# validation/normalization layered on top: it requires an explicit scheme
# (raises MissingSchema for a bare relative URL, unlike urllib3), rejects a
# handful of malformed shapes urllib3 accepts, and produces the final
# request-ready URL string. There's no reusable parsed-components object
# beyond that string, so this adapter only offers parse/reconstruct -- no
# components/query/modify_*, unlike the full parser adapters.


def _requests_prepare(url: str) -> Any:
    request = RequestsPreparedRequest()
    request.prepare_url(url, None)
    return request


def requests_reconstruct(parsed: Any) -> str:
    return parsed.url


def _create_requests_adapter() -> ParserAdapter:
    if not REQUESTS_AVAILABLE:
        reason = (
            "requests is not installed"
            if REQUESTS_IMPORT_ERROR is None
            else f"requests import failed: {REQUESTS_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="requests",
            tags=frozenset({"http-client"}),
            parse=lambda _: None,
            description="requests.models.PreparedRequest.prepare_url",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="requests",
        tags=frozenset({"http-client"}),
        parse=_requests_prepare,
        reconstructor=requests_reconstruct,
        description="requests.models.PreparedRequest.prepare_url",
    )


requests_adapter = _create_requests_adapter()
register_adapter(requests_adapter)
