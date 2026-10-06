"""End-to-end browser flow.

Drives the real viewer page in Chromium against the real uvicorn replay
service and a static file server for the viewer.  A canary HTTP server
plays the role of the "original site": archived pages reference it with
absolute URLs and <script src>, so any attempt to reach it proves a
replay leak.  The test asserts:

* the full import -> select instant/URI -> sandboxed replay flow works;
* the provenance card names the record actually selected at the instant;
* the iframe sandbox attribute carries no permission tokens;
* two-crawl time-point selection and in-frame link navigation work;
* every observed request targets only the two local services, the canary
  origin receives zero hits, and the replay response limits images via CSP.
"""

from __future__ import annotations

import http.server
import re
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from tests.warcfactory import PNG_1X1, html_record, png_record, uuid

ROOT = Path(__file__).resolve().parents[1]


class CanaryHandler(http.server.BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self):
        type(self).hits.append(self.path)
        body = b"CANARY-ORIGIN-LIVE"
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def servers(tmp_path_factory):
    canary_port = _free_port()
    viewer_port = _free_port()
    replay_port = _free_port()

    # Canary "live origin".
    CanaryHandler.hits = []
    canary = socketserver.TCPServer(("127.0.0.1", canary_port), CanaryHandler)
    thread = threading.Thread(target=canary.serve_forever, daemon=True)
    thread.start()

    viewer_dir = ROOT / "viewer"
    viewer = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(viewer_port),
         "--bind", "127.0.0.1"],
        cwd=viewer_dir,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    replay = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(replay_port)],
        cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**__import__("os").environ,
             "VIEWER_ORIGINS": f"http://localhost:{viewer_port}"},
    )

    import httpx
    deadline = time.time() + 20
    started = False
    while time.time() < deadline:
        try:
            r = httpx.get(f"http://localhost:{replay_port}/healthz", timeout=1)
            if r.status_code == 200:
                started = True
                break
        except Exception:
            time.sleep(0.3)
    if not started:
        replay.terminate()
        out = replay.stdout.read().decode(errors="replace") if replay.stdout else ""
        viewer.kill(); canary.shutdown()
        raise RuntimeError("replay service did not start:\n" + out)

    yield {
        "replay": f"http://localhost:{replay_port}",
        "viewer_port": viewer_port,
        "replay_port": replay_port,
        "canary_port": canary_port,
    }

    replay.terminate(); viewer.terminate(); canary.shutdown()
    replay.wait(timeout=5); viewer.wait(timeout=5)


@pytest.fixture(scope="module")
def browser():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("playwright not installed")
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(args=["--no-sandbox"], env={
                **__import__("os").environ,
                "LD_LIBRARY_PATH": "/tmp/pwlib/root/usr/lib/aarch64-linux-gnu:"
                                   "/tmp/pwlib/root/lib/aarch64-linux-gnu:"
                                   + __import__("os").environ.get("LD_LIBRARY_PATH", ""),
            })
        except Exception as exc:
            pytest.skip(f"chromium unavailable: {exc}")
        yield browser
        browser.close()


def _warc_file(tmp_path: Path, canary_port: int) -> Path:
    home = "https://example.test/"
    news = "https://example.test/news"
    logo = "https://example.test/i/logo.png"
    remote = f"http://127.0.0.1:{canary_port}/remote.png"

    v1 = f"""<!DOCTYPE html><html><head><title>old</title></head><body>
      <h1>旧版页面 V1</h1>
      <a href="/news">新闻页</a>
      <img src="{remote}" alt="live-only image">
      <script src="http://127.0.0.1:{canary_port}/x.js"></script>
      <img src="i/missing.png" alt="never captured">
    </body></html>"""
    v2 = f"""<!DOCTYPE html><html><body>
      <h1>新版页面 V2</h1>
      <a href="/news">新闻页</a>
      <img src="/i/logo.png" alt="logo">
      <img src="{remote}" alt="live-only image">
    </body></html>"""

    warc = b"".join([
        html_record(uuid(1), home, "2026-09-01T08:00:00Z", v1),
        html_record(uuid(2), news, "2026-09-01T08:00:05Z",
                    "<html><body><p>这是新闻页存档内容</p></body></html>"),
        html_record(uuid(3), home, "2026-09-05T09:30:00Z", v2),
        png_record(uuid(4), logo, "2026-09-05T09:30:02Z", PNG_1X1),
    ])
    path = tmp_path / "crawl.warc"
    path.write_bytes(warc)
    return path


def test_browser_flow_no_online_requests(servers, browser, tmp_path):
    from playwright.sync_api import expect

    viewer_port = servers["viewer_port"]
    replay_port = servers["replay_port"]
    canary_port = servers["canary_port"]
    viewer_url = (
        f"http://localhost:{viewer_port}/index.html"
        f"?api=http%3A%2F%2Flocalhost%3A{replay_port}"
    )

    warc_path = _warc_file(tmp_path, canary_port)
    requests_seen: list[str] = []
    csp_seen: list[str] = []

    page = browser.new_page()

    def on_request(req):
        requests_seen.append(req.url)

    def on_response(resp):
        if "/replay" in resp.url:
            csp_seen.append(resp.headers.get("content-security-policy", ""))

    page.on("request", on_request)
    page.on("response", on_response)

    # Anything that is not one of the two local services is an attempted
    # online leak: record it and abort.
    def on_route(route):
        requests_seen.append("BLOCKED:" + route.request.url)
        route.abort()

    page.route("**/*", lambda route: route.continue_())
    page.route(
        re.compile(
            rf"^https?://(?!localhost:{viewer_port}|localhost:{replay_port}"
            rf"|127\.0\.0\.1:{viewer_port}|127\.0\.0\.1:{replay_port})"
        ),
        on_route,
    )

    try:
        page.goto(viewer_url, wait_until="networkidle")

        # 1) import via the real file input
        page.set_input_files("#warc-file", str(warc_path))
        page.click("#import-form button[type=submit]")
        expect(page.locator("#stat-count")).to_have_text("4 / 10")
        assert "65,536" in page.locator("#stat-bytes").inner_text()

        # 2) choose the OLD cutoff and replay
        page.select_option("#uri-select", "https://example.test/")
        page.fill("#instant-input", "2026-09-02T00:00:00Z")
        page.click("#replay-form button[type=submit]")

        expect(page.locator("#source-card")).to_be_visible()
        expect(page.locator("#src-id")).to_have_text(f"<urn:uuid:{uuid(1)}>")
        expect(page.locator("#src-date")).to_have_text("2026-09-01T08:00:00Z")
        expect(page.locator("#src-cutoff")).to_have_text("2026-09-02T00:00:00Z")

        # iframe exists and has a fully locked-down sandbox
        frame_el = page.locator("#replay-frame")
        sandbox_token = frame_el.get_attribute("sandbox")
        assert sandbox_token == "" or sandbox_token is not None and sandbox_token.strip() == ""

        # The archived document renders the old content, sanitised.
        body = page.frame_locator("#replay-frame").locator("body")
        expect(body).to_contain_text("旧版页面 V1")
        expect(body).not_to_contain_text("新版页面 V2")
        expect(body).not_to_contain_text("<script")
        # Un-captured absolute remote image is a visible gap.
        expect(body).to_contain_text("[archived image missing")

        # 3) follow a rewritten link inside the sandboxed frame.  The
        # replay document carries its own provenance banner, so the
        # freshly navigated record identifies itself inside the frame.
        page.frame_locator("#replay-frame").locator("a", has_text="新闻页").click()
        news_body = page.frame_locator("#replay-frame").locator("body")
        expect(news_body).to_contain_text("这是新闻页存档内容")
        banner = page.frame_locator("#replay-frame").locator("#archive-provenance")
        expect(banner).to_contain_text(f"Record-ID: <urn:uuid:{uuid(2)}>")
        expect(banner).to_contain_text("https://example.test/news")

        # 4) move the cutoff past the second crawl and replay again
        page.fill("#instant-input", "2026-09-06T00:00:00Z")
        page.click("#replay-form button[type=submit]")
        body2 = page.frame_locator("#replay-frame").locator("body")
        expect(body2).to_contain_text("新版页面 V2")
        expect(page.locator("#src-id")).to_have_text(f"<urn:uuid:{uuid(3)}>")

        # give the archived logo image a moment to (not) load
        page.wait_for_timeout(800)
    finally:
        page.close()

    # 5) network audit: only the two local services were contacted
    allowed = {f"localhost:{viewer_port}", f"localhost:{replay_port}",
               f"127.0.0.1:{viewer_port}", f"127.0.0.1:{replay_port}"}
    for url in requests_seen:
        if url.startswith("data:") or url == "about:blank":
            continue
        host = url.split("/")[2]
        assert host in allowed, f"unexpected non-archive request: {url}"

    # The canary "origin" recorded no hits whatsoever.
    assert CanaryHandler.hits == [], f"live origin was contacted: {CanaryHandler.hits}"
    assert not any(u.startswith("BLOCKED:") for u in requests_seen), \
        "archived content attempted an external request"

    # Replay responses lock images to the replay service via CSP.
    assert csp_seen, "no /replay response observed"
    for csp in csp_seen:
        assert "default-src 'none'" in csp
        assert "img-src 'self'" in csp
        assert "sandbox" in csp
