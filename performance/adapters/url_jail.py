from __future__ import annotations

from performance.adapters._core import URL_JAIL_AVAILABLE, URL_JAIL_IMPORT_ERROR
from performance.adapters._core import url_jail_module as _url_jail
from performance.adapters._models import ParserAdapter
from performance.adapters._registry import register_adapter

# url_jail.validate_sync() performs *real* DNS resolution (and potentially
# live HTTP requests, per its RedirectBlocked/HttpError/Timeout surface) on
# every call -- confirmed empirically: 10 calls against the same host took
# ~30ms each, and it raises DnsError for a name that doesn't resolve rather
# than failing fast on shape alone. That makes it fundamentally unlike
# every other adapter in this suite:
#
#   - timings are not comparable to the purely-computational validators
#     (microseconds vs. tens of milliseconds is a network round-trip, not
#     a difference in validation logic)
#   - results depend on DNS/network access being available at benchmark
#     time, and will vary run to run with real-world network conditions
#   - a full-corpus benchmark run against it will be orders of magnitude
#     slower than any other adapter
#
# Tagged "network" accordingly (see _models.py's tag vocabulary) and never
# pulled in by a default --parser/--categories selection -- only when
# named explicitly.


def _url_jail_validate(url: str) -> bool:
    result = _url_jail.validate_sync(url, _url_jail.Policy.PUBLIC_ONLY)
    return bool(result)


def _create_url_jail_adapter() -> ParserAdapter:
    if not URL_JAIL_AVAILABLE:
        reason = (
            "url-jail is not installed"
            if URL_JAIL_IMPORT_ERROR is None
            else f"url-jail import failed: {URL_JAIL_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="url-jail",
            tags=frozenset({"security", "network", "validation"}),
            validator=lambda _: False,
            description="url_jail.validate_sync (Policy.PUBLIC_ONLY; performs live DNS lookups)",
            available=False,
            unavailable_reason=reason,
        )

    return ParserAdapter(
        name="url-jail",
        tags=frozenset({"security", "network", "validation"}),
        validator=_url_jail_validate,
        description="url_jail.validate_sync (Policy.PUBLIC_ONLY; performs live DNS lookups)",
    )


url_jail_adapter = _create_url_jail_adapter()
register_adapter(url_jail_adapter)
