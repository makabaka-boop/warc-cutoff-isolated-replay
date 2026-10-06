#!/usr/bin/env python3
"""Generate sample.warc: two crawls of a small site (UTF-8 HTML + PNG).

Run:  python3 tests/make_sample.py > sample.warc  (or redirect as shown)
"""

from pathlib import Path

from tests.warcfactory import PNG_1X1, PNG_2X2, html_record, png_record, uuid

HOME = "https://example.test/"
NEWS = "https://example.test/news"
LOGO = "https://example.test/i/logo.png"

v1 = """<!DOCTYPE html><html><head><title>站点首页</title></head>
<body><h1>首页 · 第一次抓取</h1>
<ul><li><a href="/news">新闻</a></li></ul></body></html>"""

v2 = """<!DOCTYPE html><html><head><title>站点首页</title></head>
<body><h1>首页 · 第二次抓取</h1>
<ul>
  <li><a href="/news">新闻</a></li>
  <li><img src="/i/logo.png" alt="logo" width="8" height="8"></li>
</ul></body></html>"""

news = "<!DOCTYPE html><html><body><p>新闻页：一切正常。</p></body></html>"


def main() -> None:
    warc = b"".join([
        html_record(uuid(1), HOME, "2026-09-01T08:00:00Z", v1),
        html_record(uuid(2), NEWS, "2026-09-01T08:00:05Z", news),
        html_record(uuid(3), HOME, "2026-09-05T09:30:00Z", v2),
        png_record(uuid(4), LOGO, "2026-09-05T09:30:02Z", PNG_2X2),
    ])
    out = Path(__file__).resolve().parents[1] / "sample.warc"
    out.write_bytes(warc)
    print(f"wrote {out} ({len(warc)} bytes, 4 records)")


if __name__ == "__main__":
    main()
