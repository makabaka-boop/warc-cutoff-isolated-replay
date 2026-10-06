"""Two-crawl scenario: time-point selection, provenance and same-instant
duplicate rejection.
"""

import pytest

from tests.warcfactory import html_record, png_record, uuid, PNG_2X2

PAGE_V1 = """<!DOCTYPE html><html><head><title>Old</title></head>
<body><h1>首页 v1</h1><p><a href="/news">新闻</a></p></body></html>"""

PAGE_V2 = """<!DOCTYPE html><html><head><title>New</title></head>
<body><h1>首页 v2</h1><p><a href="/news">新闻</a>
<img src="/i/logo.png" alt="logo"></p></body></html>"""

NEWS = "<html><body><p>新闻页</p></body></html>"

pytestmark = pytest.mark.asyncio


async def _import(client, *records):
    warc = b"".join(records)
    r = await client.post(
        "/api/import", content=warc, headers={"content-type": "application/warc"}
    )
    assert r.status_code == 200, r.text
    return r.json()


async def test_two_crawls_latest_not_after_cutoff(client):
    home = "https://example.test/"
    news = "https://example.test/news"
    logo = "https://example.test/i/logo.png"

    await _import(
        client,
        # First crawl: home + news
        html_record(uuid(1), home, "2026-09-01T08:00:00Z", PAGE_V1),
        html_record(uuid(2), news, "2026-09-01T08:00:05Z", NEWS),
        # Second crawl: home updated, logo added
        html_record(uuid(3), home, "2026-09-05T09:30:00Z", PAGE_V2),
        png_record(uuid(4), logo, "2026-09-05T09:30:02Z", PNG_2X2),
    )

    # Cutoff between the crawls -> the OLD home is selected, and its
    # /news relative link resolves to the first-crawl news page.
    r = await client.get(
        "/replay",
        params={"at": "2026-09-02T00:00:00Z", "uri": home},
    )
    assert r.status_code == 200
    assert "首页 v1" in r.text
    assert "首页 v2" not in r.text
    assert r.headers["x-archive-record-id"] == f"<urn:uuid:{uuid(1)}>"
    assert r.headers["x-archive-capture-date"] == "2026-09-01T08:00:00Z"
    from urllib.parse import unquote
    assert unquote(r.headers["x-archive-original-uri"]) == home
    # The link maps to the SAME fixed instant on the replay service.
    assert 'href="/replay?at=2026-09-02T00%3A00%3A00Z' in r.text
    assert "uri=https%3A%2F%2Fexample.test%2Fnews" in r.text

    # The news page at that instant is the first-crawl capture.
    r2 = await client.get(
        "/replay",
        params={"at": "2026-09-02T00:00:00Z", "uri": news},
    )
    assert r2.status_code == 200
    assert "新闻页" in r2.text
    assert r2.headers["x-archive-record-id"] == f"<urn:uuid:{uuid(2)}>"

    # Cutoff after the second crawl -> the NEW home and the PNG exist.
    r3 = await client.get(
        "/replay",
        params={"at": "2026-09-06T00:00:00Z", "uri": home},
    )
    assert r3.status_code == 200
    assert "首页 v2" in r3.text
    assert r3.headers["x-archive-record-id"] == f"<urn:uuid:{uuid(3)}>"
    assert 'src="/replay?at=2026-09-06T00%3A00%3A00Z' in r3.text

    img = await client.get(
        "/replay",
        params={"at": "2026-09-06T00:00:00Z", "uri": logo},
    )
    assert img.status_code == 200
    assert img.headers["content-type"] == "image/png"
    assert img.content == PNG_2X2

    # Before any crawl existed: explicit gap, never an origin fetch.
    gap = await client.get(
        "/replay",
        params={"at": "2026-08-31T00:00:00Z", "uri": home},
    )
    assert gap.status_code == 404
    assert "[archive gap]" in gap.text
    assert "No request was made to the original site" in gap.text

    # The logo referenced at the OLD instant is a gap (not captured yet);
    # the old page has no img, but a direct replay request confirms it.
    old_img = await client.get(
        "/replay",
        params={"at": "2026-09-02T00:00:00Z", "uri": logo},
    )
    assert old_img.status_code == 404


async def test_same_uri_same_instant_duplicate_rejected(client):
    home = "https://example.test/"
    body_a = html_record(uuid(1), home, "2026-09-01T08:00:00Z", "<p>a</p>")
    body_b = html_record(uuid(2), home, "2026-09-01T08:00:00Z", "<p>b</p>")

    r = await client.post(
        "/api/import",
        content=body_a + body_b,
        headers={"content-type": "application/warc"},
    )
    assert r.status_code == 409
    assert "same timestamp" in r.json()["error"] or "same instant" in r.json()["error"]

    # Nothing was imported: the batch is atomic.
    stats = (await client.get("/api/stats")).json()
    assert stats["records"] == 0
