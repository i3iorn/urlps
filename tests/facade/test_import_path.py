"""Public import path smoke tests."""

from __future__ import annotations


def test_public_import_path_urlps() -> None:
    import urlps

    assert hasattr(urlps, "parse_url")
    assert callable(urlps.parse_url)

