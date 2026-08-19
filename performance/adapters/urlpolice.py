from __future__ import annotations

from performance.adapters._core import URLPOLICE_AVAILABLE, URLPOLICE_IMPORT_ERROR, URLPolice
from performance.adapters._models import ParserAdapter
from performance.adapters._registry import register_adapter

# Benchmarking this adapter against the pathological/malicious corpora
# surfaced two real bugs in urlpolice 0.1.2 itself (not in this adapter --
# both are caught and recorded as ordinary benchmark failures, same as any
# other exception):
#
#   - It doesn't guard against urllib.parse's lazy `.port` property raising
#     ValueError on a malformed port (e.g. "http://example.com:-1/"),
#     crashing .validate() outright instead of returning an invalid result.
#   - Several inputs trigger catastrophic-backtracking-shaped slowdowns:
#     ~2.7 SECONDS per call (vs. ~45us normally) for inputs including
#     "http://_", "http://-", decimal/hex-encoded-IP SSRF-bypass attempts
#     ("http://2130706433/", "http://0x7f000001/"), and "*.local"/
#     "*.internal" hosts -- exactly the adversarial shapes a security-
#     focused SSRF validator is supposed to handle cheaply. A handful of
#     these in one dataset is enough to make that dataset's "validate"
#     benchmark take minutes instead of milliseconds; this is a genuine
#     property of the library being measured, not a bug in this benchmark
#     suite, so it's deliberately left as-is rather than worked around.


def _create_urlpolice_adapter() -> ParserAdapter:
    if not URLPOLICE_AVAILABLE:
        reason = (
            "urlpolice is not installed"
            if URLPOLICE_IMPORT_ERROR is None
            else f"urlpolice import failed: {URLPOLICE_IMPORT_ERROR}"
        )

        return ParserAdapter(
            name="urlpolice",
            tags=frozenset({"validation", "security"}),
            validator=lambda _: False,
            description="urlpolice.URLPolice (default preset)",
            available=False,
            unavailable_reason=reason,
        )

    # URLPolice() construction compiles its rule set -- ~3ms, vs. ~45us for
    # a call against an already-built instance. Build it once here, not per
    # call, or every "validate" benchmark would be timing regex compilation
    # instead of validation.
    police = URLPolice()

    return ParserAdapter(
        name="urlpolice",
        tags=frozenset({"validation", "security"}),
        validator=lambda url: police.validate(url).is_valid,
        description="urlpolice.URLPolice (default preset)",
    )


urlpolice_adapter = _create_urlpolice_adapter()
register_adapter(urlpolice_adapter)
