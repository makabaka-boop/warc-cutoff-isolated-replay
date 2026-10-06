"""Strict validation for target URIs, WARC dates and embedded HTTP responses."""
from __future__ import annotations

import datetime as _dt
import re
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

from .warc_parser import WARCFormatError

# RFC 1123, e.g. Wed, 21 Oct 2015 07:28:00 GMT
_HTTP_DATE = re.compile(
    r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), "
    r"(\d{2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4}) "
    r"(\d{2}):(\d{2}):(\d{2}) GMT$"
)
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
_REASON = re.compile(rb"^[\x20-\x7E]*$")

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

_FORBIDDEN_HTTP_HEADERS = {
    "transfer-encoding",
    "content-encoding",
    "location",
    "set-cookie",
    "www-authenticate",
}


def validate_target_uri(uri: str) -> str:
    """Validate the WARC target URI and return a canonical key."""
    if not uri or any(ch in uri for ch in (" ", '"', "<", ">", "\\")):
        raise WARCFormatError("invalid WARC-Target-URI")
    parts = urlsplit(uri)
    if parts.scheme.lower() not in ("http", "https"):
        raise WARCFormatError("WARC-Target-URI must be http(s)")
    if not parts.hostname:
        raise WARCFormatError("WARC-Target-URI has no host")
    if any(ord(ch) < 0x20 for ch in uri):
        raise WARCFormatError("control character in WARC-Target-URI")
    if parts.username or parts.password:
        raise WARCFormatError("userinfo not allowed in WARC-Target-URI")

    scheme = parts.scheme.lower()
    host = parts.hostname.lower().rstrip(".")
    default_port = (scheme == "http" and parts.port == 80) or (
        scheme == "https" and parts.port == 443
    )
    netloc = host if default_port or parts.port is None else f"{host}:{parts.port}"
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    # Collapse dot segments (RFC 3986 §5.2.4) on the same origin.
    path = urlsplit(urljoin(f"{scheme}://{netloc}/", path.lstrip("/"))).path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))  # fragment dropped


def validate_warc_date(value: str) -> str:
    m = _HTTP_DATE.match(value)
    if not m:
        raise WARCFormatError("WARC-Date must be RFC 1123 GMT, e.g. Wed, 21 Oct 2015 07:28:00 GMT")
    _, day_s, mon_s, year_s, hh, mm, ss = m.groups()
    try:
        dt = _dt.datetime(
            int(year_s), _MONTHS[mon_s], int(day_s),
            int(hh), int(mm), int(ss),
            tzinfo=_dt.timezone.utc,
        )
    except ValueError:
        raise WARCFormatError("WARC-Date is not a real calendar date")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_http_response(
    payload: bytes,
) -> tuple[int, str, dict[str, str], bytes]:
    sep = payload.find(b"\r\n\r\n")
    if sep == -1:
        raise WARCFormatError("HTTP response lacks blank line separating body")
    head = payload[:sep].split(b"\r\n")
    body = payload[sep + 4:]

    status_line = head[0]
    m = re.match(rb"^HTTP/1\.1 (\d{3}) ([\x20-\x7E]+)$", status_line)
    if not m:
        raise WARCFormatError(
            "HTTP status line must be 'HTTP/1.1 <code> <reason>'"
        )
    status = int(m.group(1))
    reason = m.group(2).decode("ascii")
    if status != 200:
        raise WARCFormatError(f"only HTTP 200 responses are stored, got {status}")

    headers: dict[str, str] = {}
    for line in head[1:]:
        if line[:1] in (b" ", b"\t"):
            raise WARCFormatError("obs-fold not allowed in HTTP headers")
        try:
            name_b, val_b = line.split(b":", 1)
        except ValueError:
            raise WARCFormatError("malformed HTTP header")
        if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name_b):
            raise WARCFormatError("illegal HTTP header name")
        if not re.fullmatch(rb"[ \t]?[\x21-\x7e]+(?:[ \t][\x21-\x7e]+)*", val_b):
            raise WARCFormatError("illegal HTTP header value")
        val = val_b.decode("ascii")
        if val.startswith((" ", "\t")):
            val = val[1:]
        if val != val.strip():
            raise WARCFormatError("bad whitespace in HTTP header value")
        key = name_b.decode("ascii").lower()
        if key in headers:
            raise WARCFormatError(f"duplicate HTTP header: {key}")
        headers[key] = val

    for forbidden in _FORBIDDEN_HTTP_HEADERS:
        if forbidden in headers:
            raise WARCFormatError(f"forbidden HTTP header on stored response: {forbidden}")

    if "content-length" not in headers:
        raise WARCFormatError("stored HTTP response must carry Content-Length")
    cl = headers["content-length"]
    if not re.fullmatch(r"\d+", cl):
        raise WARCFormatError("HTTP Content-Length must be a single integer")
    if int(cl) != len(body):
        raise WARCFormatError(
            f"HTTP Content-Length ({cl}) != actual body length ({len(body)})"
        )
    return status, reason, headers, body


def normalize_content_type(headers: dict[str, str], body: bytes) -> str:
    ctype = headers.get("content-type", "").lower()
    main, params = _parse_media_type(ctype)
    if main == "image/png":
        if not body.startswith(PNG_MAGIC):
            raise WARCFormatError("image/png body has no PNG signature")
        return "image/png"
    if main == "text/html":
        charset = params.get("charset", "utf-8")
        if charset not in ("utf-8", ""):
            raise WARCFormatError("HTML must be declared UTF-8 (charset=utf-8)")
        try:
            body.decode("utf-8")
        except UnicodeDecodeError:
            raise WARCFormatError("HTML body is not valid UTF-8")
        return "text/html; charset=utf-8"
    raise WARCFormatError(f"unsupported stored content type: {ctype or '(none)'}")


def _parse_media_type(value: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in value.split(";")]
    main = parts[0].lower()
    params: dict[str, str] = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            params[k.strip().lower()] = v.strip().lower().strip('"')
    return main, params
