# 受限 WARC 回放器（Restricted WARC Replay）

保存的网页**不会悄悄加载今天的线上图片**，归档里的脚本也**不能访问查看器**。
本应用导入一份很小、很严格的 WARC 归档，并让用户在一个**明确的截止时刻**查看
**仅来自本地归档**的历史内容；缺的内容显示“缺口”，**绝不回源**。

## 威胁模型与保证

| 风险 | 处理 |
| --- | --- |
| 归档页面偷偷加载今天的线上图片/脚本 | 所有 `src`/`href` 先解析、再映射到同一截止时刻的本地记录；映射不上就变成无 URL 的缺口标记。任何响应都带 `Content-Security-Policy: default-src 'none'; img-src 'self'`。 |
| 归档脚本访问查看器 / 偷数据 | 回放位于 `sandbox=""`（无 `allow-scripts`、无 `allow-same-origin`）的跨源 iframe；清洗器同时物理删除 `<script>` 等标签及所有事件属性。浏览器实测注入脚本被拦。 |
| 重定向 / revisit / gzip / 分块偷带内容 | 解析器只接受**未压缩** WARC/1.1、`WARC-Type: response`、内嵌 **HTTP/1.1 200**；拒绝 `Transfer-Encoding`、`Content-Encoding`、`Location` 等。 |
| 篡改记录长度 / 伪造 ID | 校验 WARC 与 HTTP 两层 `Content-Length` 与实际字节一致；`WARC-Record-ID` 唯一且为 `<...>` URI。 |
| 真假混合页面 | 每个 URI 只取**不晚于用户截止时刻的最新一条**记录；相对链接与图片固定映射到**同一时刻**；同一时刻同 URI 重复直接拒绝整份归档。页面面板显示实际记录 ID、抓取时刻、原始 URI。 |
| 非 HTML/PNG 内容 | 仅接受 `text/html; charset=utf-8`（真实 UTF-8 解码）与 `image/png`（校验 PNG 签名）。 |

## 架构（两个跨源服务，Compose 承载）

```
浏览器
 ├── http://localhost:8080  web    静态控制页（唯一可运行脚本的源；选时点/URI、展示来源）
 └── http://localhost:8000  replay 索引/选取/回放 API + 沙箱内文档（CSP 锁死，无脚本）
        └── 归档只存在于 replay 进程内存
```

* `replay/app/warc_parser.py` —— 严格、无第三方 WARC 依赖的未压缩 WARC/1.1 解析
* `replay/app/validate.py` —— 目标 URI、RFC1123 日期、HTTP 响应、UTF-8/PNG 校验
* `replay/app/rewriter.py` —— 标签/属性白名单清洗 + 首合法 `<base>` 解析 + 同时点映射
* `replay/app/storage.py` —— 内存归档与截止时刻选择（含同刻重复拒绝）
* `replay/app/main.py` —— FastAPI：`/api/import`、`/api/index`、`/api/select`、`/view/`、`/raw/`
* `web/index.html` + `app.js` —— 控制页面，iframe `sandbox=""`、`referrerpolicy="no-referrer"`
* `docker-compose.yml` —— 分别承载 `replay`（API）与 `web`（nginx 静态页）

## 导入限制

* 最多 **10 条**记录、未压缩总计 **64 KiB**（超限 413）。
* 仅 `WARC/1.1` + `WARC-Type: response` + `Content-Type: application/http;msgtype=response`。
* 内嵌负载仅 `HTTP/1.1 200`，必须有与实际字节一致的 `Content-Length`。
* 仅 `http(s)` 目标 URI（规范化：小写主机、去默认端口/点段/fragment）；日期须 RFC1123 GMT。
* 正文仅 UTF-8 HTML 或 PNG；拒绝重定向、revisit、gzip、分块传输。

## 运行

```bash
docker compose up --build
# 浏览器打开 http://localhost:8080
# 在“导入/替换归档”里选择 replay/tests/demo.warc
# 选择截止时刻（如 2015-10-21 07:30 与 2016-10-21 09:30）与 URI，点击回放
```

本地不用 Docker 的等价跑法（测试即如此运行）：

```bash
python -m uvicorn app.main:app --app-dir replay --port 8000   # WEB_ORIGIN 环境变量控制 frame-ancestors
(cd web && python -m http.server 8080)
```

## 测试

```bash
pip install -r replay/requirements.txt pytest httpx playwright
pytest replay -q                 # 23 项：解析/验证/选取/重写/安全/API
python replay/tests/make_demo.py # 生成两次抓取的演示归档
python replay/tests/test_browser_flow.py   # 一次完整浏览器流程
```

`tests/test_browser_flow.py` 记录浏览器发出的**每一个请求**，断言：
1. 两个截止时刻分别命中**第一次/第二次抓取**（固定时点，不混版）；
2. 相对图片按归档 URI（2015 视图）与首个合法 `<base>`（2016 视图）解析，
   并映射到**同一时刻**的本地 `/raw/...` PNG，且确实渲染（naturalWidth=1）；
3. 线上跟踪图、`javascript:`、外站、`<script>/<form>/<base>/on*` 全部消失或变缺口；
4. 控制页（8080）对帧（8000）**无同源访问权**；沙箱拦截脚本执行；
5. 观测到的请求**全部**来自 `localhost:8080/8000`，对 `example.com`、
   `tracker.example`、`evil.example`、`other.example` 的请求数为 **0**。
