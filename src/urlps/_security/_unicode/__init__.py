"""Unicode-aware host analysis: Script resolution, confusables, and UTS-46.

Three concerns, deliberately separate because they catch different attacks:

- :mod:`.scripts` -- UTS-39 §5.1 Highly Restrictive, per label. Catches a label
  that *mixes* scripts, e.g. ``pаypal`` (Latin p + Cyrillic а).
- :mod:`.confusables` -- whole-script confusables. Catches a label that mixes
  nothing because it is entirely non-Latin, yet reads as Latin: ``раураl``.
- :mod:`.uts46` -- the single IDNA entry point, and the Punycode *decoding*
  that both checks above depend on. Homograph attacks arrive A-label-encoded,
  and ``xn--pypal-4ve.com`` is pure ASCII, so without decoding first neither
  check ever sees anything to flag.
"""

from __future__ import annotations

from .confusables import is_whole_script_confusable, skeleton
from .scripts import UCD_VERSION, is_single_script_label, script_of, scripts_of
from .uts46 import UTS46_AVAILABLE, IdnaError, to_ascii, to_unicode

__all__ = [
    "UCD_VERSION",
    "UTS46_AVAILABLE",
    "IdnaError",
    "is_single_script_label",
    "is_whole_script_confusable",
    "script_of",
    "scripts_of",
    "skeleton",
    "to_ascii",
    "to_unicode",
]
