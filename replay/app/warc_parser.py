"""Strict parser for *uncompressed* WARC/1.1 ``response`` records.

The task deliberately forbids gzip, chunked transfer encoding, redirects and
revisit records, so instead of pulling in a permissive general-purpose WARC
library this module implements a small, strict parser.  Every field the
backend is required to verify is checked here and any deviation raises
:class:`WARCFormatError`; the API turns that into HTTP 400.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_TOTAL_BYTES = 64 * 1024
MAX_RECORDS = 10

CRLF = b"\r\n"
DOUBLE_CRLF = b"\r\n\r\n"

# Permitted WARC record headers.  Anything unknown is rejected rather than
# silently ignored: a strict, well-understood surface is a security surface.
_ALLOWED_HEADERS = {
    "warc-type": ("response",),
    "warc-record-id": None,          # validated shape
    "warc-target-uri": None,        # validated shape
    "warc-date": None,              # RFC 1123 UTC
    "content-type": None,           # application/http;msgtype=response
    "content-length": None,         # non-negative integer
}

_TOKEN = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_WARC_ID = re.compile(r"^<[\x21-\x3D\x3F-\x7E]+\x3E$", re.ASCII)  # <uri>, one pair of < >
_HTTP_FIELD = re.compile(rb"^[\x21-\x7e]+$")


class WARCFormatError(ValueError):
    """The supplied bytes are not an acceptable WARC archive."""


@dataclass(frozen=True)
class Record:
    record_id: str
    target_uri: str
    date_iso: str          # normalized YYYY-MM-DDTHH:MM:SSZ
    raw_headers: dict[str, str]
    http_status: int
    http_reason: str
    http_headers: dict[str, str]
    body: bytes
    content_type: str      # normalized "text/html; charset=utf-8" or "image/png"


def parse_archive(data: bytes) -> list[Record]:
    """Validate and parse an uncompressed WARC archive."""
    if not data:
        raise WARCFormatError("empty archive")
    if len(data) > MAX_TOTAL_BYTES:
        raise WARCFormatError(
            f"archive is {len(data)} bytes, limit is {MAX_TOTAL_BYTES}"
        )
    if not data.startswith(b"WARC/1.1"):
        raise WARCFormatError("only WARC/1.1 is accepted")

    records: list[Record] = []
    pos = 0
    seen_ids: set[str] = set()

    while pos < len(data):
        if not data.startswith(b"WARC/1.1", pos):
            raise WARCFormatError(f"record {len(records)} does not start with WARC/1.1")
        line_end = data.find(CRLF, pos)
        if line_end == -1:
            raise WARCFormatError("truncated WARC status line")
        # Exactly "WARC/1.1" (CRLF terminates it).
        if data[pos:line_end] != b"WARC/1.1":
            raise WARCFormatError("unsupported WARC version")

        hdr_end = data.find(DOUBLE_CRLF, line_end)
        if hdr_end == -1:
            raise WARCFormatError("unterminated WARC header block")
        block = data[line_end + 2:hdr_end]
        if block == b"":
            raise WARCFormatError("record with no WARC headers")

        headers = _parse_header_block(block, name="WARC")
        try:
            length = int(headers["content-length"])
        except (KeyError, ValueError):
            raise WARCFormatError("missing or non-integer Content-Length")
        if length < 0:
            raise WARCFormatError("negative Content-Length")

        body_start = hdr_end + 4
        body_end = body_start + length
        if body_end > len(data):
            raise WARCFormatError(
                "Content-Length exceeds remaining bytes (truncated record)"
            )
        payload = data[body_start:body_end]
        # Every record must be followed by CRLF CRLF per WARC chapter 5.
        if data[body_end:body_end + 4] != DOUBLE_CRLF:
            raise WARCFormatError("record not followed by CRLF CRLF")
        pos = body_end + 4

        record = _build_record(headers, payload, seen_ids)
        seen_ids.add(record.record_id)
        records.append(record)

    if not records:
        raise WARCFormatError("archive contains no records")
    if len(records) > MAX_RECORDS:
        raise WARCFormatError(f"{len(records)} records, limit is {MAX_RECORDS}")
    return records


def _parse_header_block(block: bytes, name: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in block.split(CRLF):
        if raw == b"":
            continue
        if raw[:1] in (b" ", b"\t"):
            raise WARCFormatError(f"obs-fold (continuation line) not allowed in {name}")
        try:
            name_b, val_b = raw.split(b":", 1)
        except ValueError:
            raise WARCFormatError(f"malformed {name} header line")
        if not _TOKEN.fullmatch(name_b):
            raise WARCFormatError(f"illegal {name} header name")
        # Exactly one optional leading OWS space, then VCHAR tokens with no
        # trailing whitespace and no embedded control characters.
        if not re.fullmatch(rb"[ \t]?[\x21-\x7e]+(?:[ \t][\x21-\x7e]+)*", val_b):
            raise WARCFormatError(f"illegal {name} header value")
        # Only the leading single whitespace that separates value from colon.
        val = val_b.decode("ascii")
        if val.startswith((" ", "\t")):
            val = val[1:]
        if val != val.strip():
            raise WARCFormatError(f"bad whitespace in {name} header value")
        key = name_b.decode("ascii").lower()
        if key in headers:
            raise WARCFormatError(f"duplicate {name} header: {key}")
        headers[key] = val
    return headers


def _build_record(headers: dict[str, str], payload: bytes, seen_ids: set[str]) -> Record:
    for key, value in headers.items():
        if key not in _ALLOWED_HEADERS:
            raise WARCFormatError(f"unexpected WARC header: {key}")
        allowed = _ALLOWED_HEADERS[key]
        if allowed is not None and value.lower() not in allowed:
            raise WARCFormatError(f"WARC header {key}: unsupported value {value!r}")

    rid = headers["warc-record-id"]
    if not _WARC_ID.match(rid) or rid.count("<") != 1 or rid.count(">") != 1:
        raise WARCFormatError("WARC-Record-ID must be <urn:uuid:...> style URI")
    if rid in seen_ids:
        raise WARCFormatError(f"duplicate WARC-Record-ID: {rid}")

    from .validate import (
        validate_target_uri,
        validate_warc_date,
        validate_http_response,
        normalize_content_type,
    )

    target_uri = headers["warc-target-uri"]
    canonical_uri = validate_target_uri(target_uri)
    date_iso = validate_warc_date(headers["warc-date"])

    ctype = headers["content-type"].lower()
    ct_main, ct_params = _parse_media_type(ctype)
    if ct_main != "application/http" or ct_params.get("msgtype") != "response":
        raise WARCFormatError(
            'WARC Content-Type must be application/http;msgtype=response'
        )

    status, reason, http_headers, body = validate_http_response(payload)
    norm_type = normalize_content_type(http_headers, body)

    return Record(
        record_id=rid,
        target_uri=canonical_uri,
        date_iso=date_iso,
        raw_headers=headers,
        http_status=status,
        http_reason=reason,
        http_headers=http_headers,
        body=body,
        content_type=norm_type,
    )


def _parse_media_type(value: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in value.split(";")]
    main = parts[0].lower()
    params: dict[str, str] = {}
    for p in parts[1:]:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        params[k.strip().lower()] = v.strip().lower()
    return main, params
