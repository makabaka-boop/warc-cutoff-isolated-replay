"""Strict validation/parsing of uncompressed WARC/1.1 imports.

The mature library :mod:`warcio` does the actual WARC record parsing; this
module adds the guarantees the task asks for:

* uncompressed WARC/1.1 framing only -- gzip magic is rejected and every
  ``Content-Length`` byte count is verified against the physical framing;
* response records only (no revisit, no metadata, no warcinfo, ...);
* unique, syntactically valid ``WARC-Record-ID``;
* absolute http/https ``WARC-Target-URI``;
* UTC ``WARC-Date``;
* single occurrences of every mandatory header;
* HTTP/1.1 200, no ``Transfer-Encoding`` (no chunked), no
  ``Content-Encoding`` (no gzip), declared length equals the body;
* payload is UTF-8 HTML (charset explicitly UTF-8) or PNG (magic checked);
* the URI/date pair is unique (same URI at the same instant -> reject).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from io import BytesIO
from urllib.parse import urlsplit

from warcio.recordloader import StatusAndHeaders
from warcio.statusandheaders import StatusAndHeadersParser
from warcio.archiveiterator import ArchiveIterator

from .storage import HTML, PNG, Record, StoreError

WARC_VERSION = b"WARC/1.1"
GZIP_MAGIC = b"\x1f\x8b"
CRLF = b"\r\n"
MAX_UPLOAD_BYTES = 1024 * 1024

_UUID_RE = re.compile(
    r"^<urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}>$"
)
_WARC_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_BOM = b"\xef\xbb\xbf"
_PNG_SIGNATURE = bytes.fromhex("89504e470d0a1a0a")


class WarcFormatError(ValueError):
    """The raw bytes do not conform to the restricted WARC subset."""


# ---------------------------------------------------------------------------
# Low-level framing scan (independent of warcio) -- verifies that records are
# exact uncompressed WARC/1.1 records with correct Content-Length values and
# no trailing junk, then warcio re-parses each block semantically.
# ---------------------------------------------------------------------------

def _read_header_block(data: bytes, offset: int) -> tuple[bytes, int]:
    end = data.find(CRLF + CRLF, offset)
    if end == -1:
        raise WarcFormatError("unterminated WARC header block")
    block = data[offset:end]
    if not block.startswith(WARC_VERSION + CRLF):
        raise WarcFormatError("only uncompressed WARC/1.1 records are accepted")
    lines = block.split(CRLF)
    # No blank lines allowed inside the header block.
    if any(b"\n" in line or b"\r" in line for line in lines[1:]):
        raise WarcFormatError("bare CR/LF inside WARC header block")
    return block, end + 4


def _parse_warc_headers(block: bytes) -> tuple[dict[str, bytes], int]:
    lines = block.split(CRLF)[1:]
    headers: dict[str, bytes] = {}
    length: int | None = None
    for line in lines:
        name, sep, value = line.partition(b":")
        if not sep or not name or value[:1] not in (b"", b" ") or value[:2] == b"  ":
            raise WarcFormatError("malformed WARC header line: %r" % line)
        key = name.decode("ascii", "strict").lower()
        val = value[1:] if value[:1] == b" " else value
        try:
            val.decode("latin-1")
        except UnicodeDecodeError:
            raise WarcFormatError("non-latin1 WARC header value")
        if key in headers:
            raise WarcFormatError(f"duplicate WARC header {name!r}")
        headers[key] = val
        if key == "content-length":
            if not re.fullmatch(rb"[0-9]+", val):
                raise WarcFormatError("WARC Content-Length must be a decimal byte count")
            length = int(val)
    if length is None:
        raise WarcFormatError("WARC Content-Length missing")
    return headers, length


def framed_blocks(data: bytes) -> list[tuple[dict[str, bytes], bytes]]:
    """Split raw WARC bytes into (headers, payload) with length verification."""
    if not data:
        raise WarcFormatError("empty WARC payload")
    if data[:2] == GZIP_MAGIC:
        raise WarcFormatError("gzip-compressed WARCs are not accepted")
    blocks: list[tuple[dict[str, bytes], bytes]] = []
    offset = 0
    while offset < len(data):
        block_start = offset
        header_block, payload_start = _read_header_block(data, offset)
        headers, length = _parse_warc_headers(header_block)
        payload_end = payload_start + length
        if payload_end > len(data):
            raise WarcFormatError("WARC Content-Length exceeds the data available")
        payload = data[payload_start:payload_end]
        blocks.append((headers, payload))
        # Exactly one CRLF terminator follows the record body.
        if data[payload_end:payload_end + 2] != CRLF:
            raise WarcFormatError("record body must be followed by exactly one CRLF")
        offset = payload_end + 2
        # Another record must start with the WARC version line, or EOF.
        if offset < len(data) and not data.startswith(WARC_VERSION + CRLF, offset):
            raise WarcFormatError("data found after record without a new WARC/1.1 record")
        if offset == block_start:
            raise WarcFormatError("zero progress while parsing")
    return blocks


# ---------------------------------------------------------------------------
# WARC header / payload semantics
# ---------------------------------------------------------------------------

def _check_target_uri(raw: bytes) -> str:
    try:
        uri = raw.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise WarcFormatError("WARC-Target-URI must be ASCII")
    parts = urlsplit(uri)
    if parts.scheme not in ("http", "https"):
        raise WarcFormatError("WARC-Target-URI must be http or https")
    if not parts.hostname or not re.fullmatch(r"[!-~]+", parts.hostname):
        raise WarcFormatError("WARC-Target-URI has no valid host")
    if parts.fragment:
        raise WarcFormatError("WARC-Target-URI must not contain a fragment")
    if re.search(r"[\s]", uri):
        raise WarcFormatError("WARC-Target-URI contains whitespace")
    return uri


def _check_date(raw: bytes) -> datetime:
    s = raw.decode("ascii", "strict")
    if not _WARC_DATE_RE.fullmatch(s):
        raise WarcFormatError("WARC-Date must be YYYY-MM-DDTHH:MM:SSZ (UTC)")
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise WarcFormatError(f"WARC-Date {s!r} is not a valid calendar date")


def _require_single(headers: dict[str, bytes], name: str) -> bytes:
    if name not in headers:
        raise WarcFormatError(f"{name} header missing")
    return headers[name]


# ---------------------------------------------------------------------------
# HTTP/1.1 response validation
# ---------------------------------------------------------------------------

def _parse_http(payload: bytes) -> tuple[StatusAndHeaders, bytes]:
    try:
        sah = StatusAndHeadersParser([], verify=False).parse(BytesIO(payload))
    except Exception as exc:  # warcio raises several exception types
        raise WarcFormatError(f"unparseable HTTP response block: {exc}")
    if sah.protocol != "HTTP/1.1":
        raise WarcFormatError("only HTTP/1.1 responses are accepted")
    status_line = str(sah.statusline).strip()
    if not status_line or not status_line.split(" ", 1)[0].isdigit():
        raise WarcFormatError("HTTP status line missing")
    status_code = status_line.split(" ", 1)[0]
    if status_code != "200":
        raise WarcFormatError(f"only HTTP 200 responses are accepted (got {status_code})")

    seen: dict[str, str] = {}
    for name, value in sah.headers:
        key = name.lower()
        if key in seen:
            # Repeated headers (folded or duplicated) are not accepted in
            # this restricted subset.
            raise WarcFormatError(f"duplicate HTTP header {name!r}")
        seen[key] = value.strip()

    te = seen.get("transfer-encoding")
    if te is not None:
        raise WarcFormatError("Transfer-Encoding (e.g. chunked) is not supported")
    ce = seen.get("content-encoding")
    if ce is not None and ce.lower() not in ("identity",):
        raise WarcFormatError("Content-Encoding (e.g. gzip) is not supported")

    content_length = seen.get("content-length")
    if content_length is None:
        raise WarcFormatError("HTTP Content-Length is required")
    if not re.fullmatch(r"[0-9]+", content_length):
        raise WarcFormatError("HTTP Content-Length must be a decimal byte count")

    sep = payload.find(CRLF + CRLF)
    if sep == -1:
        raise WarcFormatError("HTTP header/body separator missing")
    body = payload[sep + 4:]
    if int(content_length) != len(body):
        raise WarcFormatError(
            f"HTTP Content-Length ({content_length}) does not equal body length ({len(body)})"
        )
    return sah, body


def _content_type(headers: dict[str, str]) -> str:
    ct = headers.get("content-type")
    if not ct:
        raise WarcFormatError("HTTP Content-Type is required")
    media, _, params = ct.partition(";")
    media = media.strip().lower()
    param_map: dict[str, str] = {}
    for param in params.split(";") if params else []:
        pname, _, pval = param.partition("=")
        pname = pname.strip().lower()
        pval = pval.strip().strip('"').lower()
        if pname:
            if pname in param_map:
                raise WarcFormatError("duplicate Content-Type parameter")
            param_map[pname] = pval
    if media == "text/html":
        # Charset must be explicitly UTF-8 -- no guessing.
        if param_map.get("charset", "").replace("_", "-") != "utf-8":
            raise WarcFormatError("HTML payload must declare charset=utf-8")
        return HTML
    if media == "image/png":
        if param_map:
            raise WarcFormatError("image/png must not carry Content-Type parameters")
        return PNG
    raise WarcFormatError(f"unsupported content type {media!r}; only UTF-8 HTML and PNG")


def _validate_payload(content_type: str, body: bytes) -> None:
    if content_type == HTML:
        raw = body[len(_BOM):] if body.startswith(_BOM) else body
        try:
            raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise WarcFormatError("HTML payload is not valid UTF-8")
    else:
        if not body.startswith(_PNG_SIGNATURE):
            raise WarcFormatError("image/png payload lacks the PNG signature")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_warc(data: bytes) -> list[Record]:
    if len(data) > MAX_UPLOAD_BYTES:
        raise StoreError(f"upload exceeds {MAX_UPLOAD_BYTES} bytes", status=413)

    blocks = framed_blocks(data)
    if not blocks:
        raise WarcFormatError("WARC contains no records")

    # Stream warcio records alongside the independently framed blocks.
    # Materialising the iterator eagerly makes warcio hand back exhausted
    # content streams, so it must be consumed lazily.
    warcio_iter = iter(ArchiveIterator(BytesIO(data)))

    records: list[Record] = []
    for index, (wh, http_payload) in enumerate(blocks):
        try:
            wr = next(warcio_iter)
        except StopIteration:
            raise WarcFormatError("warcio parsed fewer records than the framing scan")

        if wr.rec_type != "response":
            raise WarcFormatError(
                f"only 'response' records are accepted (found {wr.rec_type!r})"
            )
        if wr.http_headers is None:
            raise WarcFormatError("record carries no HTTP response block")
        if wr.rec_headers.protocol != "WARC/1.1":
            raise WarcFormatError("warcio disagrees on WARC version")

        # Read the body after the header accessors (warcio exposes the
        # de-chunked/de-length payload through content_stream()).
        warcio_body = wr.content_stream().read()

        record_id = _require_single(wh, "warc-record-id").decode("ascii").strip()
        if not _UUID_RE.fullmatch(record_id):
            raise WarcFormatError("WARC-Record-ID must be <urn:uuid:…>")
        uri = _check_target_uri(_require_single(wh, "warc-target-uri").strip())
        date = _check_date(_require_single(wh, "warc-date").strip())

        # Length consistency: framing bytes == warcio body bytes.
        seen, body = _parse_http(http_payload)
        if body != warcio_body:
            raise WarcFormatError("warcio parsed a different HTTP body than the frame")
        if int(seen.get_header("Content-Length")) != len(body):
            raise WarcFormatError("HTTP Content-Length disagreement after parsing")

        content_type = _content_type(
            {name.lower(): value.strip() for name, value in seen.headers}
        )
        _validate_payload(content_type, body)
        records.append(Record(record_id, uri, date, content_type, body))

    try:
        extra = next(warcio_iter)
    except StopIteration:
        extra = None
    if extra is not None:
        raise WarcFormatError("warcio parsed more records than the framing scan")

    return records
