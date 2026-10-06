"""Import validation: framing, lengths, IDs, URI/date, content rules,
limits and forbidden encodings/transfer features.
"""

import pytest

from tests.warcfactory import (
    PNG_1X1,
    gzip_warc,
    html_record,
    http_response,
    png_record,
    uuid,
    warc_record,
)

pytestmark = pytest.mark.asyncio


async def _post(client, raw: bytes):
    return await client.post(
        "/api/import", content=raw,
        headers={"content-type": "application/warc"},
    )


async def test_valid_import_and_limits(client):
    r = await _post(client, html_record(uuid(1), "https://e.test/",
                                        "2026-09-01T08:00:00Z", "<p>ok</p>"))
    assert r.status_code == 200, r.text
    assert r.json()["stats"]["records"] == 1


async def test_gzip_rejected(client):
    gz = gzip_warc([html_record(uuid(1), "https://e.test/",
                                "2026-09-01T08:00:00Z", "<p>x</p>")])
    r = await _post(client, gz)
    assert r.status_code == 400
    assert "gzip" in r.json()["error"].lower()


async def test_revisit_and_other_types_rejected(client):
    body = http_response("text/html; charset=utf-8", b"<p>x</p>")
    for bad_type in ("revisit", "metadata", "request", "warcinfo"):
        rec = warc_record(uuid(5), "https://e.test/", "2026-09-01T08:00:00Z",
                          body, rec_type=bad_type)
        r = await _post(client, rec)
        assert r.status_code == 400
        assert "response" in r.json()["error"]


async def test_duplicate_record_id_rejected(client):
    a = html_record(uuid(1), "https://e.test/a", "2026-09-01T08:00:00Z", "<p>a</p>")
    b = html_record(uuid(1), "https://e.test/b", "2026-09-01T08:00:01Z", "<p>b</p>")
    r = await _post(client, a + b)
    assert r.status_code == 409
    assert "WARC-Record-ID" in r.json()["error"]


async def test_bad_target_uri(client):
    for bad in ("ftp://e.test/x", "mailto:a@b", "https://",
                "https://e.test/#frag", "not a uri"):
        rec = html_record(uuid(7), bad, "2026-09-01T08:00:00Z", "<p>x</p>")
        r = await _post(client, rec)
        assert r.status_code == 400, (bad, r.text)


async def test_bad_date(client):
    for bad in ("2026-09-01T08:00:00", "2026-13-40T99:99:99Z",
                "2026-09-01 08:00:00Z", "not-a-date"):
        rec = html_record(uuid(8), "https://e.test/", bad, "<p>x</p>")
        r = await _post(client, rec)
        assert r.status_code == 400, (bad, r.text)


async def test_content_length_must_match(client):
    body = b"<p>x</p>"
    block = http_response("text/html; charset=utf-8", body)
    # Claim fewer bytes than physically present.
    rec = warc_record(uuid(9), "https://e.test/", "2026-09-01T08:00:00Z",
                      block, override_length=len(block) - 5)
    r = await _post(client, rec)
    assert r.status_code == 400

    # HTTP Content-Length lies about the HTTP body.
    lying = http_response("text/html; charset=utf-8", body,
                          extra_headers=[("Content-Length", "999")])
    # Our helper normally emits a truthful Content-Length after; build by hand.
    raw = ("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
           "Content-Length: 999\r\n\r\n").encode() + body
    rec2 = warc_record(uuid(10), "https://e.test/", "2026-09-01T08:00:00Z", raw)
    r2 = await _post(client, rec2)
    assert r2.status_code == 400
    assert "Content-Length" in r2.json()["error"]


async def test_chunked_and_content_encoding_rejected(client):
    body = b"<p>x</p>"
    chunked = http_response(
        "text/html; charset=utf-8", body,
        extra_headers=[("Transfer-Encoding", "chunked")])
    r = await _post(client, warc_record(
        uuid(11), "https://e.test/", "2026-09-01T08:00:00Z", chunked))
    assert r.status_code == 400
    assert "Transfer-Encoding" in r.json()["error"]

    encoded = http_response(
        "text/html; charset=utf-8", body,
        extra_headers=[("Content-Encoding", "gzip")])
    r2 = await _post(client, warc_record(
        uuid(12), "https://e.test/", "2026-09-01T08:00:00Z", encoded))
    assert r2.status_code == 400
    assert "Content-Encoding" in r2.json()["error"]


async def test_only_utf8_html_and_png(client):
    # HTML without explicit charset is rejected (no guessing).
    raw = http_response("text/html", "<p>x</p>".encode())
    r = await _post(client, warc_record(
        uuid(13), "https://e.test/", "2026-09-01T08:00:00Z", raw))
    assert r.status_code == 400 and "charset" in r.json()["error"]

    # Latin-1 bytes under a utf-8 label are rejected.
    raw = http_response("text/html; charset=utf-8", "café".encode("latin-1"))
    r = await _post(client, warc_record(
        uuid(14), "https://e.test/", "2026-09-01T08:00:00Z", raw))
    assert r.status_code == 400 and "UTF-8" in r.json()["error"]

    # Other media types rejected.
    raw = http_response("text/css", b"body{}")
    r = await _post(client, warc_record(
        uuid(15), "https://e.test/x.css", "2026-09-01T08:00:00Z", raw))
    assert r.status_code == 400

    # PNG label with non-PNG body rejected.
    raw = http_response("image/png", b"GIF89a fake")
    r = await _post(client, warc_record(
        uuid(16), "https://e.test/x.png", "2026-09-01T08:00:00Z", raw))
    assert r.status_code == 400 and "PNG" in r.json()["error"]

    # Real PNG accepted.
    r = await _post(client, png_record(
        uuid(17), "https://e.test/x.png", "2026-09-01T08:00:00Z", PNG_1X1))
    assert r.status_code == 200


async def test_non_200_rejected(client):
    block = http_response("text/html; charset=utf-8", b"<p>moved</p>",
                          status="302",
                          extra_headers=[("Location", "https://e.test/")])
    # helper writes "302 OK" status text; craft explicitly
    raw = (b"HTTP/1.1 302 Found\r\nContent-Type: text/html; charset=utf-8\r\n"
           b"Content-Length: 11\r\nLocation: https://e.test/\r\n\r\n<p>moved</p>")
    r = await _post(client, warc_record(
        uuid(18), "https://e.test/", "2026-09-01T08:00:00Z", raw))
    assert r.status_code == 400
    assert "200" in r.json()["error"]


async def test_record_count_limit(client):
    recs = b"".join(
        html_record(uuid(20 + i), f"https://e.test/p{i}",
                    "2026-09-01T08:00:00Z", "<p>x</p>")
        for i in range(11)
    )
    r = await _post(client, recs)
    assert r.status_code == 413
    assert "10" in r.json()["error"]


async def test_total_byte_limit(client):
    # First record alone is under the cap; the second tips the total over.
    big = "<p>" + ("x" * 60_000) + "</p>"
    recs = (
        html_record(uuid(30), "https://e.test/big",
                    "2026-09-01T08:00:00Z", big)
        + html_record(uuid(31), "https://e.test/small",
                      "2026-09-01T08:00:01Z", "<p>" + "y" * 6_000 + "</p>")
    )
    r = await _post(client, recs)
    assert r.status_code == 413
    assert "65536" in r.json()["error"]

    # Atomicity: neither record landed.
    stats = (await client.get("/api/stats")).json()
    assert stats["records"] == 0


async def test_bad_framing_rejected(client):
    good = html_record(uuid(40), "https://e.test/",
                       "2026-09-01T08:00:00Z", "<p>x</p>")
    # Truncated body.
    r = await _post(client, good[:-10])
    assert r.status_code == 400
    # Wrong version.
    r = await _post(client, good.replace(b"WARC/1.1", b"WARC/1.0", 1))
    assert r.status_code == 400
    # Trailing junk.
    r = await _post(client, good + b"junk")
    assert r.status_code == 400


async def test_invalid_instant_rejected(client):
    r = await client.get("/replay", params={
        "at": "2026-09-01 08:00:00", "uri": "https://e.test/"})
    assert r.status_code == 400
