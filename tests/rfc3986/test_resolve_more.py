"""Additional coverage for _resolve.py: type validation."""

from __future__ import annotations

import pytest

from urlps._resolve import split_uri_reference


def test_split_uri_reference_rejects_non_string():
    with pytest.raises(TypeError, match="reference must be str"):
        split_uri_reference(123)  # type: ignore[arg-type]
