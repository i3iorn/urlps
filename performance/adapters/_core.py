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
    from rfc3986 import exceptions as rfc3986_exceptions
    from rfc3986 import validators as rfc3986_validators

    RFC3986_AVAILABLE = True
    RFC3986_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    rfc3986 = None  # type: ignore[assignment]
    rfc3986_api = None  # type: ignore[assignment]
    rfc3986_exceptions = None  # type: ignore[assignment]
    rfc3986_validators = None  # type: ignore[assignment]
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


# uritools
try:
    import uritools

    URITOOLS_AVAILABLE = True
    URITOOLS_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    uritools = None  # type: ignore[assignment]
    URITOOLS_AVAILABLE = False
    URITOOLS_IMPORT_ERROR = exc


# pywhatwgurl
try:
    from pywhatwgurl import URL as WhatwgURL

    PYWHATWGURL_AVAILABLE = True
    PYWHATWGURL_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    WhatwgURL = None  # type: ignore[assignment,misc]
    PYWHATWGURL_AVAILABLE = False
    PYWHATWGURL_IMPORT_ERROR = exc


# pydantic
try:
    from pydantic import AnyUrl as PydanticAnyUrl
    from pydantic import HttpUrl as PydanticHttpUrl
    from pydantic import ValidationError as PydanticValidationError

    PYDANTIC_AVAILABLE = True
    PYDANTIC_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    PydanticAnyUrl = None  # type: ignore[assignment,misc]
    PydanticHttpUrl = None  # type: ignore[assignment,misc]
    PydanticValidationError = None  # type: ignore[assignment,misc]
    PYDANTIC_AVAILABLE = False
    PYDANTIC_IMPORT_ERROR = exc


# validators
try:
    import validators as validators_module

    VALIDATORS_AVAILABLE = True
    VALIDATORS_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    validators_module = None  # type: ignore[assignment]
    VALIDATORS_AVAILABLE = False
    VALIDATORS_IMPORT_ERROR = exc


# url-normalize
try:
    from url_normalize import url_normalize

    URL_NORMALIZE_AVAILABLE = True
    URL_NORMALIZE_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    url_normalize = None  # type: ignore[assignment]
    URL_NORMALIZE_AVAILABLE = False
    URL_NORMALIZE_IMPORT_ERROR = exc


# rfc3987
try:
    import rfc3987 as rfc3987_module

    RFC3987_AVAILABLE = True
    RFC3987_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    rfc3987_module = None  # type: ignore[assignment]
    RFC3987_AVAILABLE = False
    RFC3987_IMPORT_ERROR = exc


# Hyperlink
try:
    from hyperlink import URLParseError as HyperlinkParseError
    from hyperlink import parse as hyperlink_parse

    HYPERLINK_AVAILABLE = True
    HYPERLINK_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    hyperlink_parse = None  # type: ignore[assignment]
    HyperlinkParseError = None  # type: ignore[assignment,misc]
    HYPERLINK_AVAILABLE = False
    HYPERLINK_IMPORT_ERROR = exc


# requests
try:
    from requests.models import PreparedRequest as RequestsPreparedRequest

    REQUESTS_AVAILABLE = True
    REQUESTS_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    RequestsPreparedRequest = None  # type: ignore[assignment,misc]
    REQUESTS_AVAILABLE = False
    REQUESTS_IMPORT_ERROR = exc


# httpx
try:
    from httpx import URL as HttpxURL

    HTTPX_AVAILABLE = True
    HTTPX_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    HttpxURL = None  # type: ignore[assignment,misc]
    HTTPX_AVAILABLE = False
    HTTPX_IMPORT_ERROR = exc


# url-jail
#
# NOTE: url_jail.validate_sync() performs *real* DNS resolution (and, per
# its Policy/RedirectBlocked/HttpError surface, potentially live HTTP
# requests) on every call -- it is the only adapter in this suite that does
# real network I/O per benchmarked operation. Timings are therefore not
# comparable to the purely-computational adapters, results depend on
# network/DNS access being available, and a benchmark run against it will
# be orders of magnitude slower. Tagged "network" (see _models.py) and
# never included unless named explicitly.
try:
    import url_jail as url_jail_module

    URL_JAIL_AVAILABLE = True
    URL_JAIL_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    url_jail_module = None  # type: ignore[assignment]
    URL_JAIL_AVAILABLE = False
    URL_JAIL_IMPORT_ERROR = exc


# urlpolice
try:
    from urlpolice import URLPolice

    URLPOLICE_AVAILABLE = True
    URLPOLICE_IMPORT_ERROR: Exception | None = None
except ImportError as exc:
    URLPolice = None  # type: ignore[assignment,misc]
    URLPOLICE_AVAILABLE = False
    URLPOLICE_IMPORT_ERROR = exc
