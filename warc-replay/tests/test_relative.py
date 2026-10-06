"""Relative resolution: archived base URI + first legal <base href>, then
mapping to the frozen instant on the replay service.
"""

import json
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from tests.warcfactory import html_record, png_record, uuid, PNG_1X1, PNG_2X2

pytestmark = pytest.mark.asyncio

DOC = "https://example.test/a/b/page.html"
SIBLING = "https://example.test/a/b/sibling.html"
PARENT = "https://example.test/a/parent.html"
ROOT = "https://example.test/root.png"
ABS = "https://example.test/deep/abs.html"
OTHER_HOST = "https://cdn.example.test/p.png"
BASE_TARGET = "https://example.test/base/from-base.png"
ILLEGAL_BASE_TARGET = "https://evil.test/x.png"


async def _setup(client, html: str, extras=None):
    records = [html_record(uuid(1), DOC, "2026-09-01T08:00:00Z", html)]
    if extras:
        records.extend(extras)
    warc = b"".join(records)
    r = await client.post("/api/import", content=warc,
                          headers={"content-type": "application/warc"})
    assert r.status_code == 200, r.text


SIBLING_PNG = "https://example.test/a/b/sibling.png"


async def test_relative_links_and_images(client):
    html = """<html><body>
      <a href="sibling.html">sibling</a>
      <a href="../parent.html">parent</a>
      <a href="/root.png">root-png-from-a-link</a>
      <img src="sibling.png" alt="s">
      <img src="/root.png" alt="r">
      <img src="../missing.png" alt="m">
      <a href="https://other.example.net/x">offsite</a>
      <a href="mailto:x@y">mailto</a>
    </body></html>"""
    await _setup(client, html, extras=[
        html_record(uuid(3), SIBLING, "2026-09-01T08:00:02Z", "<p>sib</p>"),
        html_record(uuid(4), PARENT, "2026-09-01T08:00:03Z", "<p>parent</p>"),
        png_record(uuid(5), ROOT, "2026-09-01T08:00:04Z", PNG_2X2),
        png_record(uuid(6), SIBLING_PNG, "2026-09-01T08:00:05Z", PNG_1X1),
    ])

    r = await client.get("/replay", params={
        "at": "2026-09-02T00:00:00Z", "uri": DOC})
    assert r.status_code == 200
    refs = json.loads(unquote(r.headers["x-archive-references"]))
    statuses = {(e["raw"], e["status"]) for e in refs}

    # All present references map locally; missing/offsite/scheme -> gap.
    assert ("sibling.html", "mapped") in statuses
    assert ("../parent.html", "mapped") in statuses
    assert ("sibling.png", "mapped") in statuses
    assert ("/root.png", "mapped") in statuses
    # a link to a PNG (not HTML) is a gap for navigation
    assert ("/root.png", "gap") in statuses
    assert ("../missing.png", "gap") in statuses
    assert ("https://other.example.net/x", "gap") in statuses
    assert ("mailto:x@y", "gap") in statuses

    # Every mapped href points at the replay service, same instant.
    for href in _attrs(r.text, "href"):
        if href.startswith("/replay"):
            q = parse_qs(urlparse(href).query)
            assert q["at"] == ["2026-09-02T00:00:00Z"]
    for src in _attrs(r.text, "src"):
        assert src.startswith("/replay?at=2026-09-02T00%3A00%3A00Z"), src

    # Gap anchor became an inert span marker (no href).
    assert "mailto:x@y" not in r.text
    assert "[link unavailable in archive]" in r.text
    # Missing image became a visible placeholder, not an <img>.
    assert "[archived image missing" in r.text


async def test_first_legal_base_is_honoured(client):
    html = """<html><head>
      <base href="https://evil.test/ignored/">
      <base href="https://example.test/base/">
    </head><body>
      <img src="from-base.png" alt="b">
    </body></html>"""
    await _setup(client, html, extras=[
        png_record(uuid(7), BASE_TARGET, "2026-09-01T08:00:06Z", PNG_1X1),
        png_record(uuid(8), ILLEGAL_BASE_TARGET, "2026-09-01T08:00:07Z", PNG_1X1),
    ])
    r = await client.get("/replay", params={
        "at": "2026-09-02T00:00:00Z", "uri": DOC})
    assert r.status_code == 200
    # Relative image resolved against the first *legal* same-host base.
    refs = json.loads(unquote(r.headers["x-archive-references"]))
    assert refs[0]["status"] == "mapped"
    assert refs[0]["resolved_to"] == BASE_TARGET
    assert "<base" not in r.text.lower()


async def test_base_never_leaves_archive_host(client):
    html = """<html><head><base href="https://evil.test/"></head>
      <body><img src="x.png" alt="x"></body></html>"""
    await _setup(client, html, extras=[
        png_record(uuid(9), "https://evil.test/x.png",
                   "2026-09-01T08:00:08Z", PNG_1X1),
    ])
    r = await client.get("/replay", params={
        "at": "2026-09-02T00:00:00Z", "uri": DOC})
    assert r.status_code == 200
    refs = json.loads(unquote(r.headers["x-archive-references"]))
    # Illegal base ignored: resolved against the document URI, which has
    # no such image -> gap; the captured evil.test image is never used.
    assert refs[0]["status"] == "gap"
    assert "archive-gap" in r.text


def _attrs(markup, name):
    import re
    return re.findall(rf'{name}="([^"]*)"', markup)
