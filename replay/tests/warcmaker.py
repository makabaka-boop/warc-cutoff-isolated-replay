"""Helpers to build strict, uncompressed WARC/1.1 archives in tests."""
from __future__ import annotations

import datetime as _dt


def http_date(dt: _dt.datetime) -> str:
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")


def warc_record(
    *,
    record_id: str,
    uri: str,
    dt: _dt.datetime,
    content_type: str,
    body: bytes,
    extra_headers: list[tuple[str, str]] | None = None,
    raw_http: bytes | None = None,
) -> bytes:
    if raw_http is not None:
        payload = raw_http
    else:
        payload = (
            b"HTTP/1.1 200 OK\r\n"
            + f"Content-Type: {content_type}\r\n".encode()
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"\r\n"
            + body
        )
    rid = record_id.strip()
    if rid.startswith("<") and rid.endswith(">"):
        rid = rid[1:-1]
    lines = [
        b"WARC/1.1",
        b"WARC-Type: response",
        f"WARC-Record-ID: <{rid}>".encode(),
        f"WARC-Target-URI: {uri}".encode(),
        f"WARC-Date: {http_date(dt)}".encode(),
        b"Content-Type: application/http;msgtype=response",
        f"Content-Length: {len(payload)}".encode(),
    ]
    for k, v in extra_headers or []:
        lines.append(f"{k}: {v}".encode())
    head = b"\r\n".join(lines)
    return head + b"\r\n\r\n" + payload + b"\r\n\r\n"


def archive(*records: bytes) -> bytes:
    return b"".join(records)


# 1x1 transparent PNG (67 bytes), then a second valid 2x2 PNG.
PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
    "890000000d49444154789c6360000002000154a24f5f0000000049454e44ae42"
    "6082"
)
PNG_2X2 = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000002000000020806000000754b"
    "a25b0000001349444154789c63600002240101d383d72b0000000049454e44ae"
    "426082"
)
