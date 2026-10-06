"""Helpers for building the restricted uncompressed WARC/1.1 test fixtures."""

from __future__ import annotations

import struct
import zlib
from datetime import datetime, timezone

def minimal_png(width: int = 1, height: int = 1,
                rgba: tuple[int, int, int, int] = (0, 0, 0, 0)) -> bytes:
    sig = bytes.fromhex("89504e470d0a1a0a")

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    px = bytes(rgba)
    raw = b"".join(b"\x00" + px * width for _ in range(height))
    idat = zlib.compress(raw)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


PNG_1X1 = minimal_png(1, 1, (200, 30, 30, 255))
PNG_2X2 = minimal_png(2, 2, (30, 120, 200, 255))


def http_response(content_type: str, body: bytes, status: str = "200",
                  extra_headers: list[tuple[str, str]] | None = None,
                  omit_content_length: bool = False) -> bytes:
    headers = [("Content-Type", content_type)]
    if not omit_content_length:
        headers.append(("Content-Length", str(len(body))))
    if extra_headers:
        headers.extend(extra_headers)
    head = "HTTP/1.1 " + status + " OK\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in headers)
    head += "\r\n"
    return head.encode("ascii") + body


def warc_record(record_id: str, uri: str, date: str, http_block: bytes,
                rec_type: str = "response", extra_headers=None,
                override_length: int | None = None) -> bytes:
    if isinstance(date, datetime):
        date = date.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    headers = [
        ("WARC-Type", rec_type),
        ("WARC-Record-ID", f"<urn:uuid:{record_id}>"),
        ("WARC-Date", date),
        ("WARC-Target-URI", uri),
        ("Content-Type", "application/http; msgtype=response"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    length = len(http_block) if override_length is None else override_length
    headers.append(("Content-Length", str(length)))
    out = b"WARC/1.1\r\n" + b"".join(
        f"{k}: {v}\r\n".encode("ascii") for k, v in headers
    ) + b"\r\n" + http_block + b"\r\n"
    return out


def html_record(record_id: str, uri: str, date: str, html: str | bytes,
                **kw) -> bytes:
    body = html.encode("utf-8") if isinstance(html, str) else html
    return warc_record(
        record_id, uri, date,
        http_response("text/html; charset=utf-8", body), **kw
    )


def png_record(record_id: str, uri: str, date: str, png: bytes = PNG_1X1,
               **kw) -> bytes:
    return warc_record(
        record_id, uri, date, http_response("image/png", png), **kw
    )


def gzip_warc(records: list[bytes]) -> bytes:
    comp = zlib.compressobj(wbits=31)
    out = b"".join(comp.compress(r) for r in records) + comp.flush()
    return out


def uuid(n: int) -> str:
    # Deterministic UUID-shaped ids: 00000000-0000-0000-0000-{zero-padded}
    return f"00000000-0000-0000-0000-{n:012d}"
