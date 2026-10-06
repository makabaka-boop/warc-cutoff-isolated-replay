"""One browser flow proving the replay never touches the live web.

Run while the replay service (8000) and static page (8080) are up::

    LD_LIBRARY_PATH=... python tests/test_browser_flow.py

The flow:
  1. loads the real control page served on :8080,
  2. records *every* network request the browser makes,
  3. replays two cutoffs (2015 crawl, 2016 crawl) of the same URI,
  4. asserts the only requests ever made are localhost (page + replay),
     i.e. no request to example.com / tracker.example / evil.example,
  5. asserts the frame is script-less sandboxed, scripts/forms/base are gone,
     relative links/images map to same-cutoff local records, and gaps are shown.
"""
from __future__ import annotations

import os
import pathlib
import sys

from playwright.sync_api import sync_playwright

REPLAY = "http://localhost:8000"
WEB = "http://localhost:8080"
DEMO = pathlib.Path(__file__).with_name("demo.warc")

failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    print(("PASS" if cond else "FAIL"), "-", msg)
    if not cond:
        failures.append(msg)


def main() -> int:
    requests_seen: list[str] = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context()

        page = context.new_page()
        page.on("request", lambda r: requests_seen.append(r.url))
        # Console errors are informative; CSP violations show up here too.
        page.on("console", lambda m: print("   console:", m.type, m.text[:120]))

        # The demo archive is already imported by the test harness; load the
        # real control page and wait for its fetch() of the index to populate.
        page.goto(WEB + "/index.html")
        page.wait_for_function(
            "() => document.querySelectorAll('#uri option').length >= 4",
            timeout=8000,
        )

        # Re-import the demo archive exactly the way the UI does, then reload
        # to prove the browser-driven import path works end to end.
        page.evaluate("document.querySelector('details').open = true")
        page.set_input_files("#warcfile", str(DEMO))
        page.click("#upload")
        page.wait_for_function(
            "() => document.querySelectorAll('#uri option').length >= 4",
            timeout=8000,
        )

        # -------- cutoff 1: 2015 crawl -----------------------------------
        page.fill("#cutoff", "2015-10-21T07:30")
        page.select_option("#uri", "http://example.com/")
        page.click("#go")

        def replay_frame():
            for f in page.frames:
                if f.url.startswith(REPLAY + "/view/"):
                    return f
            return None

        frame = page.wait_for_function(
            "() => Array.from(document.querySelectorAll('iframe'))"
            ".some(f => f.src.startsWith('http://localhost:8000/view/'))",
            timeout=5000,
        )
        rf = replay_frame()
        rf.wait_for_load_state("networkidle", timeout=8000)

        # The page (8080) must NOT have same-origin access into the frame (8000)
        cross_origin_blocked = page.evaluate(
            "() => { try { return document.getElementById('frame').contentDocument === null; }"
            " catch (e) { return true; } }"
        )
        check(cross_origin_blocked,
              "control page has NO same-origin access to the replay frame")

        frame_el = page.locator("#frame")
        sandbox = frame_el.get_attribute("sandbox")
        check(sandbox == "", f"iframe sandbox attribute is empty (value={sandbox!r})")

        body_text_2015 = rf.evaluate("() => document.body.textContent")
        html_2015 = rf.evaluate("() => document.documentElement.outerHTML")
        check("第一次抓取" in body_text_2015, "2015 cutoff shows the FIRST crawl")
        check("第二次抓取" not in body_text_2015, "2015 cutoff does NOT show the 2016 crawl")
        check("<script" not in html_2015.lower(), "no <script> in replayed frame")
        check("<form" not in html_2015.lower(), "no <form> in replayed frame")
        check("<base" not in html_2015.lower(), "no <base> in replayed frame")
        check("onload" not in html_2015.lower(), "no event handler attributes")
        # relative image mapped to the replay service at the SAME cutoff
        imgs_2015 = rf.evaluate(
            "() => Array.from(document.images).map(i=>({src:i.src, raw:i.getAttribute('src')}))"
        )
        check(
            any(i["src"] == REPLAY + "/raw/2015-10-21T07:30:00Z/http://example.com/assets/logo.png"
                for i in imgs_2015),
            "relative <img> rewritten to same-cutoff replay /raw record",
        )
        # the online tracker image must have become an inert gap span
        check(
            not any(i["raw"] and "tracker.example" in i["raw"] for i in imgs_2015)
            and not any(i["src"] and "tracker.example" in i["src"] for i in imgs_2015),
            "online tracker image URL is not present as any img src",
        )
        gap_text = rf.evaluate(
            "() => Array.from(document.querySelectorAll('[data-gap]'))"
            ".map(e=>e.textContent).join('|')"
        )
        check("gap" in gap_text, "a visible gap marker is shown for missing/online content")
        meta = page.locator("#frame-meta").inner_text()
        check("2015-10-21T07:28:00Z" in meta, f"provenance shows actual 2015 capture ({meta!r})")
        check(page.locator("#m-rec").inner_text().startswith("<urn:uuid:1111"),
              "actual record id shown (2015 record)")

        # -------- cutoff 2: 2016 crawl, <base> relative resolution --------
        page.fill("#cutoff", "2016-10-21T09:30")
        page.click("#go")
        page.wait_for_timeout(500)
        rf2 = replay_frame()
        rf2.wait_for_load_state("networkidle", timeout=8000)
        body_text_2016 = rf2.evaluate("() => document.body.textContent")
        html_2016 = rf2.evaluate("() => document.documentElement.outerHTML")
        check("第二次抓取" in body_text_2016, "2016 cutoff shows the SECOND crawl")
        check("第一次抓取" not in body_text_2016, "2016 cutoff does NOT show the 2015 crawl")
        check("<base" not in html_2016.lower(), "<base> removed after being used")
        check("javascript:alert" not in html_2016, "javascript: link neutralized")
        check("evil.example" not in html_2016, "no evil.example URL remains in DOM")
        imgs_2016 = rf2.evaluate(
            "() => Array.from(document.images).map(i=>i.src).join('\\n')"
        )
        check(
            REPLAY + "/raw/2016-10-21T09:30:00Z/http://example.com/dir/logo.png"
            in imgs_2016,
            "base-relative logo maps to same-cutoff /dir/logo.png local record",
        )
        check("evil.example" not in imgs_2016, "no external image request URL in DOM")
        meta2 = page.locator("#frame-meta").inner_text()
        check("2016-10-21T09:00:00Z" in meta2, f"provenance shows actual 2016 capture ({meta2!r})")

        # give the browser a moment to issue any (forbidden) subresource loads
        page.wait_for_timeout(500)

        # -------- the key assertion: NO live-web request ever -------------
        external = [
            u for u in requests_seen
            if not (u.startswith(WEB) or u.startswith(REPLAY)
                    or u in ("about:blank",) or u.startswith("data:"))
        ]
        print("\n--- all requests observed ---")
        for u in dict.fromkeys(requests_seen):
            print("  ", u)
        print("------------------------------\n")
        check(external == [],
              f"ZERO requests to any non-local origin (unexpected: {external})")
        for forbidden in ("example.com/", "tracker.example", "evil.example", "other.example"):
            hit = [u for u in requests_seen if forbidden in u and "localhost" not in u]
            check(not hit, f"no request contains {forbidden!r} off-localhost")

        # navigation inside the sandboxed frame must be inert too: click a
        # rewritten local link and confirm it stays on the replay origin.
        page.fill("#cutoff", "2015-10-21T07:30")
        page.click("#go")
        page.wait_for_timeout(500)
        rf3 = replay_frame()
        rf3.wait_for_load_state("networkidle", timeout=8000)
        hrefs = rf3.evaluate(
            "() => Array.from(document.querySelectorAll('a'))"
            ".map(a=>a.getAttribute('href'))"
        )
        check(all(h is None or h.startswith("/view/") for h in hrefs),
              f"every surviving anchor points to a local /view/ URL ({hrefs})")

        browser.close()

    print()
    if failures:
        print(f"{len(failures)} CHECK(S) FAILED")
        return 1
    print("ALL BROWSER-FLOW CHECKS PASSED — replay is fixed-instant and never goes online")
    return 0


if __name__ == "__main__":
    sys.exit(main())
