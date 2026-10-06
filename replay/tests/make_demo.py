"""Build the demo archive (two crawls, relative paths, malicious HTML)."""
import datetime as dt
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from tests.warcmaker import PNG_1X1, PNG_2X2, archive, warc_record

out = pathlib.Path(__file__).with_name("demo.warc")

D1 = dt.datetime(2015, 10, 21, 7, 28, 0, tzinfo=dt.timezone.utc)
D2 = dt.datetime(2016, 10, 21, 9, 0, 0, tzinfo=dt.timezone.utc)
DP1 = dt.datetime(2015, 10, 21, 7, 20, 0, tzinfo=dt.timezone.utc)
DP2 = dt.datetime(2016, 10, 21, 9, 5, 0, tzinfo=dt.timezone.utc)

html1 = (
    "<!DOCTYPE html><html><head><title>示例站 · 2015</title>"
    "<script>alert('x')</script>"
    "<style>body{color:red}</style></head>"
    "<body onload='alert(1)'>"
    "<h1>公司主页（第一次抓取）</h1>"
    "<p>联系页面使用相对链接：<a href=\"contact.html\">联系我们</a></p>"
    "<p>Logo 是相对路径图片：<img src=\"assets/logo.png\" alt=\"logo\"></p>"
    "<p>线上图片必须成为缺口：<img src=\"https://tracker.example/px.png?u=1\" alt=\"x\"></p>"
    "<p><a href=\"http://other.example/\">外站链接</a></p>"
    "<table><tr><th>年份</th><td>2015</td></tr></table>"
    "</body></html>"
).encode("utf-8")

html2 = (
    "<!DOCTYPE html><html><head><title>示例站 · 2016</title>"
    "<base href=\"/dir/\">"
    "<script src=\"http://evil.example/x.js\"></script></head>"
    "<body>"
    "<h1>公司主页（第二次抓取）</h1>"
    "<form action=\"/steal\"><input name=\"q\"><button>go</button></form>"
    "<p><a href=\"contact.html\">联系我们（相对 base /dir/ 解析）</a></p>"
    "<p><img src=\"logo.png\" alt=\"logo\" onerror=\"fetch('http://evil')\"></p>"
    "<p><iframe src=\"http://evil\"></iframe>"
    "<p><a href=\"javascript:alert(1)\">危险链接</a></p>"
    "<p><object data=\"x.swf\"></object></p>"
    "</body></html>"
).encode("utf-8")

contact = (
    "<!DOCTYPE html><html><body><h1>联系</h1>"
    "<p><a href=\"/\">返回首页</a></p></body></html>"
).encode("utf-8")

records = [
    warc_record(record_id="urn:uuid:11111111-1111-1111-1111-111111111111",
                uri="http://example.com/", dt=D1,
                content_type="text/html; charset=utf-8", body=html1),
    warc_record(record_id="urn:uuid:22222222-2222-2222-2222-222222222222",
                uri="http://example.com/", dt=D2,
                content_type="text/html; charset=utf-8", body=html2),
    warc_record(record_id="urn:uuid:33333333-3333-3333-3333-333333333333",
                uri="http://example.com/contact.html", dt=D1,
                content_type="text/html; charset=utf-8", body=contact),
    warc_record(record_id="urn:uuid:44444444-4444-4444-4444-444444444444",
                uri="http://example.com/dir/contact.html", dt=D2,
                content_type="text/html; charset=utf-8", body=contact),
    warc_record(record_id="urn:uuid:55555555-5555-5555-5555-555555555555",
                uri="http://example.com/assets/logo.png", dt=DP1,
                content_type="image/png", body=PNG_1X1),
    warc_record(record_id="urn:uuid:66666666-6666-6666-6666-666666666666",
                uri="http://example.com/dir/logo.png", dt=DP2,
                content_type="image/png", body=PNG_2X2),
]

data = archive(*records)
assert len(data) <= 64 * 1024, len(data)
out.write_bytes(data)
print(f"wrote {out} ({len(data)} bytes, {len(records)} records)")
