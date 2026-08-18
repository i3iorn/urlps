from __future__ import annotations

# yarl
try:
    from yarl import URL as YarlURL

    YARL_AVAILABLE = True
    YARL_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    YarlURL = None  # type: ignore[assignment,misc]
    YARL_AVAILABLE = False
    YARL_IMPORT_ERROR = exc


# rfc3986
try:
    import rfc3986
    from rfc3986 import api as rfc3986_api

    RFC3986_AVAILABLE = True
    RFC3986_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    rfc3986 = None  # type: ignore[assignment]
    rfc3986_api = None  # type: ignore[assignment]
    RFC3986_AVAILABLE = False
    RFC3986_IMPORT_ERROR = exc


# furl
try:
    from furl import furl as Furl

    FURL_AVAILABLE = True
    FURL_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    Furl = None  # type: ignore[assignment,misc]
    FURL_AVAILABLE = False
    FURL_IMPORT_ERROR = exc


# urllib3
try:
    from urllib3.util import parse_url as urllib3_parse_url

    URLLIB3_AVAILABLE = True
    URLLIB3_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    urllib3_parse_url = None  # type: ignore[assignment]
    URLLIB3_AVAILABLE = False
    URLLIB3_IMPORT_ERROR = exc
