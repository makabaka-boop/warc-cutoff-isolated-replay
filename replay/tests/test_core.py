import datetime as dt

import pytest

from app.storage import ARCHIVE
from app.warc_parser import WARCFormatError, parse_archive
from app.rewriter import sanitize_and_rewrite
from app.validate import validate_target_uri
from tests.warcmaker import PNG_1X1, archive, warc_record

D1 = dt.datetime(2015, 10, 21, 7, 28, 0, tzinfo=dt.timezone.utc)
D2 = dt.datetime(2016, 10, 21, 9, 0, 0, tzinfo=dt.timezone.utc)


def html_record(rid, uri, when, html):
    return warc_record(record_id=rid, uri=uri, dt=when,
                       content_type="text/html; charset=utf-8", body=html)


def png_record(rid, uri, when, body=PNG_1X1):
    return warc_record(record_id=rid, uri=uri, dt=when,
                       content_type="image/png", body=body)


# ---------------- parser / validation --------------------------------------

def test_parses_valid_two_crawl_archive():
    recs = parse_archive(
        archive(
            html_record("<urn:1>", "http://e.com/", D1, b"<html>1</html>"),
            html_record("<urn:2>", "http://e.com/", D2, b"<html>2</html>"),
        )
    )
    assert len(recs) == 2
    assert recs[0].target_uri == "http://e.com/"
    assert recs[0].date_iso == "2015-10-21T07:28:00Z"
    assert recs[0].content_type == "text/html; charset=utf-8"


def test_rejects_gzip_magic():
    data = archive(html_record("<urn:1>", "http://e.com/", D1, b"<html/>"))
    with pytest.raises(WARCFormatError, match="WARC/1.1"):
        parse_archive(b"\x1f\x8b" + data)


def test_rejects_warc_10_and_non_response():
    good = archive(html_record("<urn:1>", "http://e.com/", D1, b"<html/>"))
    bad = good.replace(b"WARC/1.1", b"WARC/1.0", 1)
    with pytest.raises(WARCFormatError):
        parse_archive(bad)
    with pytest.raises(WARCFormatError, match="warc-type"):
        parse_archive(archive(warc_record(
            record_id="urn:uuid:00000000-0000-0000-0000-00000000000u", uri="http://e.com/", dt=D1,
            content_type="text/html; charset=utf-8", body=b"<html/>",
            extra_headers=[("WARC-Type", "revisit")])))


def test_rejects_chunked_gzip_transfer_and_redirect():
    base = warc_record(record_id="urn:uuid:00000000-0000-0000-0000-00000000000u", uri="http://e.com/", dt=D1,
                       content_type="text/html; charset=utf-8", body=b"<html/>")
    # redirect
    rec = warc_record(record_id="urn:uuid:00000000-0000-0000-0000-00000000000u", uri="http://e.com/", dt=D1,
                      content_type="text/html", body=b"",
                      raw_http=b"HTTP/1.1 301 Moved\r\nLocation: http://x/\r\n"
                               b"Content-Length: 0\r\n\r\n")
    with pytest.raises(WARCFormatError, match="only HTTP 200"):
        parse_archive(archive(rec))
    # chunked
    rec = warc_record(record_id="urn:uuid:00000000-0000-0000-0000-00000000000u", uri="http://e.com/", dt=D1,
                      content_type="text/html", body=b"",
                      raw_http=b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
    with pytest.raises(WARCFormatError, match="transfer-encoding"):
        parse_archive(archive(rec))
    # gzip content encoding
    rec = warc_record(record_id="urn:uuid:00000000-0000-0000-0000-00000000000u", uri="http://e.com/", dt=D1,
                      content_type="text/html", body=b"x",
                      raw_http=b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
                               b"Content-Type: text/html; charset=utf-8\r\n"
                               b"Content-Length: 1\r\n\r\nx")
    with pytest.raises(WARCFormatError, match="content-encoding"):
        parse_archive(archive(rec))


def test_rejects_bad_record_lengths_and_duplicate_ids():
    rec = warc_record(record_id="urn:uuid:00000000-0000-0000-0000-00000000000u",
                      uri="http://e.com/", dt=D1,
                      content_type="text/html; charset=utf-8", body=b"<html/>")
    # Inflate the WARC Content-Length beyond the bytes actually present.
    import re
    tampered = re.sub(rb"Content-Length: (\d+)", lambda m: b"Content-Length: " + str(int(m.group(1)) + 50).encode(), rec, count=1)
    with pytest.raises(WARCFormatError, match="exceeds remaining"):
        parse_archive(archive(tampered))
    dup = archive(
        html_record("<same>", "http://e.com/a", D1, b"<html/>"),
        html_record("<same>", "http://e.com/b", D1, b"<html/>"),
    )
    with pytest.raises(WARCFormatError, match="duplicate WARC-Record-ID"):
        parse_archive(dup)


def test_rejects_bad_uri_scheme_and_date():
    with pytest.raises(WARCFormatError, match="http"):
        parse_archive(archive(html_record("<u>", "ftp://e.com/a", D1, b"<h/>")))
    rec = warc_record(record_id="urn:uuid:00000000-0000-0000-0000-00000000000u", uri="http://e.com/", dt=D1,
                      content_type="text/html; charset=utf-8", body=b"<h/>")
    bad = rec.replace(b"Wed, 21 Oct 2015 07:28:00 GMT", b"Wed, 21 Oct 2015 07:28:00 +0000")
    with pytest.raises(WARCFormatError, match="WARC-Date"):
        parse_archive(archive(bad))


def test_rejects_non_utf8_html_and_fake_png():
    rec = warc_record(record_id="urn:uuid:00000000-0000-0000-0000-00000000000u", uri="http://e.com/", dt=D1,
                      content_type="text/html; charset=utf-8",
                      body=b"\xff\xfe<html/>")
    with pytest.raises(WARCFormatError, match="UTF-8"):
        parse_archive(archive(rec))
    rec = warc_record(record_id="urn:uuid:00000000-0000-0000-0000-00000000000u", uri="http://e.com/p.png", dt=D1,
                      content_type="image/png", body=b"NOT A PNG")
    with pytest.raises(WARCFormatError, match="PNG signature"):
        parse_archive(archive(rec))


def test_rejects_same_instant_same_uri():
    data = archive(
        html_record("<a>", "http://e.com/", D1, b"<html/>"),
        html_record("<b>", "http://e.com/", D1, b"<html>x</html>"),
    )
    with pytest.raises(WARCFormatError, match="same instant"):
        ARCHIVE.load(data)


def test_limits_ten_records_and_64k():
    recs = [
        html_record(f"<u{i}>", f"http://e.com/p{i}", D1, b"<html/>")
        for i in range(11)
    ]
    with pytest.raises(WARCFormatError, match="limit is 10"):
        parse_archive(archive(*recs))
    big = b"x" * 65450
    recs = [html_record("<u>", "http://e.com/", D1, big)]
    with pytest.raises(WARCFormatError, match="65536"):
        parse_archive(archive(*recs))


def test_uri_canonicalization():
    assert validate_target_uri("HTTP://Example.COM:80/a/../b?x=1#frag") \
        == "http://example.com/b?x=1"


# ---------------- selection -------------------------------------------------

@pytest.fixture()
def store():
    ARCHIVE.load(archive(
        html_record("<a>", "http://example.com/", D1, b"<html>old</html>"),
        html_record("<b>", "http://example.com/", D2, b"<html>new</html>"),
        png_record("<c>", "http://example.com/p.png", D1),
    ))
    return ARCHIVE


def test_cutoff_picks_newest_not_later(store):
    from app.storage import _parse_cutoff
    mid = _parse_cutoff("2016-01-01T00:00:00Z")
    rec = store.lookup_at("http://example.com/", mid)
    assert rec.record_id == "<a>"
    rec = store.lookup_at("http://example.com/", _parse_cutoff("2020-01-01T00:00Z"))
    assert rec.record_id == "<b>"
    assert store.lookup_at("http://example.com/", _parse_cutoff("2015-01-01T00:00Z")) is None


# ---------------- rewriting / sanitization ---------------------------------

def _rewrite(html, uri="http://example.com/", cutoff="2016-10-21T09:00:00Z"):
    from app.storage import _parse_cutoff
    cdt = _parse_cutoff(cutoff)
    return sanitize_and_rewrite(
        html.encode("utf-8"), uri, cutoff,
        lambda u: ARCHIVE.lookup_at(u, cdt),
        lambda u, c, raw: f"/{'raw' if raw else 'view'}/{c}/{u}",
    )


def test_whitelist_strips_scripts_forms_events_styles_embeds(store):
    evil = (
        "<html><head><script>alert(1)</script><style>p{}</style>"
        "<link rel=stylesheet href='http://x/x.css'></head>"
        "<body onload=alert(1)>"
        "<form action='/x'><input name=q><button>b</button></form>"
        "<p onclick='evil()' class='x'>hi</p>"
        "<table><tr><td colspan='2'>cell</td></tr></table>"
        "<a href='x' onmouseover='evil()' style='color:red'>l</a>"
        "<iframe src='http://evil'></iframe><object data='x'></object>"
        "<embed src='x'><svg onload=alert(1)/>"
        "</body></html>"
    )
    res = _rewrite(evil)
    out = res.html
    for banned in ("<script", "<style", "<form", "<input", "<button", "<iframe",
                   "<object", "<embed", "<svg", "<link", "onload", "onclick",
                   "onmouseover", "style=", "class=", "action="):
        assert banned not in out, banned
    assert "<td" in out and "colspan=" in out and "cell" in out
    assert "hi" in out  # text survives


def test_relative_links_and_images_resolve_then_map(store):
    page = (
        "<html><body>"
        "<a href='p.png'>png link</a>"
        "<img src='p.png' alt='logo'>"
        "<img src='missing.png'>"
        "<a href='contact.html'>contact</a>"
        "</body></html>"
    )
    res = _rewrite(page)
    # image relative to archive URI -> same-cutoff raw record
    assert "/raw/2016-10-21T09:00:00Z/http://example.com/p.png" in res.html
    # missing image is replaced, no src pointing anywhere
    assert "data-gap" in res.html
    # p.png is an image, so its *link* becomes a gap (not archived HTML)
    assert "target is not archived HTML" in res.gaps.__str__()
    # link to missing HTML also gaps
    assert any("contact.html" in g and "no capture" in g for g in res.gaps)


def test_first_legal_base_used_and_removed(store):
    page = (
        "<html><head><base href='/dir/'><base href='http://other/'></head>"
        "<body><img src='logo.png'></body></html>"
    )
    store.load(archive(
        html_record("<a>", "http://example.com/", D2, b"<html/>"),
        png_record("<c>", "http://example.com/dir/logo.png", D1),
    ))
    res = _rewrite(page)
    assert res.base_href == "http://example.com/dir/"
    assert "<base" not in res.html
    assert "/raw/2016-10-21T09:00:00Z/http://example.com/dir/logo.png" in res.html


def test_other_schemes_and_external_become_gaps_never_rewritten(store):
    page = (
        "<html><body>"
        "<a href='javascript:alert(1)'>x</a>"
        "<a href='mailto:a@b.c'>m</a>"
        "<img src='http://tracker.example/px.png'>"
        "<a href='http://other.example/'>ext</a>"
        "</body></html>"
    )
    res = _rewrite(page)
    assert "javascript:alert" not in res.html
    assert "mailto:" not in res.html
    assert "tracker.example" not in res.html
    assert "other.example" not in res.html  # no archived capture -> gap text
    assert any("non-http" in g for g in res.gaps)
    assert res.html.count("<a ") == 0  # no live anchors remain


def test_cutoff_rewriting_uses_same_instant_for_embedded_image():
    store = ARCHIVE
    store.load(archive(
        html_record("<a>", "http://example.com/", D1,
                    b"<html><body><img src='logo.png'></body></html>"),
        png_record("<old>", "http://example.com/logo.png",
                   dt.datetime(2014, 1, 1, tzinfo=dt.timezone.utc)),
        png_record("<new>", "http://example.com/logo.png", D2),
    ))
    old = _rewrite(
        "<html><body><img src='logo.png'></body></html>",
        cutoff="2015-10-21T07:28:00Z")
    assert "http://example.com/logo.png" in old.html
    assert old.gaps == []  # old png exists before cutoff -> mapped
