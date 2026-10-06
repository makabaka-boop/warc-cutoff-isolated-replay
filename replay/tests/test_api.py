"""End-to-end API checks against the FastAPI app (no network egress mocked)."""
import datetime as dt
import pathlib

from fastapi.testclient import TestClient

from app.main import app
from tests.warcmaker import PNG_1X1, archive, warc_record

client = TestClient(app, raise_server_exceptions=False)

D1 = dt.datetime(2015, 10, 21, 7, 28, 0, tzinfo=dt.timezone.utc)
D2 = dt.datetime(2016, 10, 21, 9, 0, 0, tzinfo=dt.timezone.utc)
DP = dt.datetime(2015, 10, 21, 7, 20, 0, tzinfo=dt.timezone.utc)

HTML1 = (
    b"<html><body><h1>Old</h1>"
    b"<a href='contact.html'>c</a>"
    b"<img src='assets/logo.png' alt='l'>"
    b"<img src='https://tracker.example/p.png'>"
    b"</body></html>"
)
HTML2 = (
    b"<html><head><base href='/dir/'></head><body><h1>New</h1>"
    b"<script>alert(1)</script><img src=logo.png onerror=alert(1)>"
    b"</body></html>"
)


def _load_demo():
    recs = [
        warc_record(record_id="urn:uuid:11111111-1111-1111-1111-111111111111",
                    uri="http://example.com/", dt=D1,
                    content_type="text/html; charset=utf-8", body=HTML1),
        warc_record(record_id="urn:uuid:22222222-2222-2222-2222-222222222222",
                    uri="http://example.com/", dt=D2,
                    content_type="text/html; charset=utf-8", body=HTML2),
        warc_record(record_id="urn:uuid:55555555-5555-5555-5555-555555555555",
                    uri="http://example.com/assets/logo.png", dt=DP,
                    content_type="image/png", body=PNG_1X1),
    ]
    r = client.post("/api/import", content=archive(*recs))
    assert r.status_code == 200, r.text


def test_import_and_index():
    _load_demo()
    r = client.get("/api/index")
    assert r.status_code == 200
    data = r.json()
    assert data["record_count"] == 3
    assert any(u["uri"] == "http://example.com/" and len(u["captures"]) == 2
               for u in data["uris"])


def test_select_picks_record_by_cutoff():
    _load_demo()
    r = client.get("/api/select?cutoff=2016-01-01T00:00:00Z&uri=http://example.com/")
    assert r.status_code == 200
    assert r.json()["record_id"] == "<urn:uuid:11111111-1111-1111-1111-111111111111>"
    r = client.get("/api/select?cutoff=2020-01-01T00:00:00Z&uri=http://example.com/")
    assert r.json()["record_id"] == "<urn:uuid:22222222-2222-2222-2222-222222222222>"
    # before first capture -> gap
    r = client.get("/api/select?cutoff=2010-01-01T00:00:00Z&uri=http://example.com/")
    assert r.status_code == 404 and r.json()["gap"] is True


def test_view_csp_sandbox_and_rewrite():
    _load_demo()
    r = client.get("/view/2020-01-01T00:00:00Z/http://example.com/")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "img-src 'self'" in csp
    assert "sandbox" in csp
    assert "frame-ancestors" in csp
    body = r.text
    assert "<script" not in body and "onerror" not in body
    assert "<base" not in body
    # relative image resolved via the page's first legal <base> /dir/ and
    # mapped to a same-cutoff local raw record (gap in this fixture: only
    # assets/logo.png is stored) -- either way no live URL remains.
    assert "tracker.example" not in body
    assert "replay-provenance" in body
    assert r.headers["x-warc-record-id"] == "<urn:uuid:22222222-2222-2222-2222-222222222222>"


def test_view_old_cutoff_uses_relative_assets():
    _load_demo()
    r = client.get("/view/2015-12-31T23:59:59Z/http://example.com/")
    assert "/raw/2015-12-31T23:59:59Z/http://example.com/assets/logo.png" in r.text
    assert "Old" in r.text and "New" not in r.text


def test_raw_png_served_other_types_gap():
    _load_demo()
    r = client.get("/raw/2020-01-01T00:00:00Z/http://example.com/assets/logo.png")
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/png"
    assert r.content[:8] == bytes.fromhex("89504e470d0a1a0a")
    # HTML URI through /raw is a 404, never the HTML bytes
    r = client.get("/raw/2020-01-01T00:00:00Z/http://example.com/")
    assert r.status_code == 404
    # missing URI through /view is an explicit gap page
    r = client.get("/view/2020-01-01T00:00:00Z/http://example.com/nope")
    assert r.status_code == 404
    assert "Content gap" in r.text
    assert "not contacted" in r.text


def test_import_rejects_oversize_and_malformed():
    r = client.post("/api/import", content=b"x" * 65537)
    assert r.status_code == 413
    r = client.post("/api/import", content=b"not warc")
    assert r.status_code == 400
    assert "WARC/1.1" in r.json()["error"]


def test_replay_headers_on_every_kind_of_response():
    _load_demo()
    for path in [
        "/api/index",
        "/view/2020-01-01T00:00:00Z/http://example.com/",
        "/view/2020-01-01T00:00:00Z/http://example.com/missing",
        "/raw/2020-01-01T00:00:00Z/http://example.com/missing.png",
    ]:
        h = client.get(path).headers
        assert h["x-content-type-options"] == "nosniff"
        assert h["referrer-policy"] == "no-referrer"
        assert "no-store" in h["cache-control"]
