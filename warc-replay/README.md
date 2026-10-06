# 受限 WARC 时点回放

一个**绝不回源**的 Web 归档回放应用：用户在页面上选择「原 URI + 截止时刻」，
系统从内存归档中选取该 URI **不晚于该时刻的最新一次**抓取，清洗后放进
无脚本、无同源权限的 sandbox iframe 里展示，并明确标出实际命中的记录来源。
缺失的记录、其他协议、不支持的内容类型都渲染为可见「缺口」，不会静默加载
今天的线上图片，归档脚本也接触不到查看器。

## 架构

`docker compose up` 启动两个相互独立的服务：

| 服务      | 端口  | 职责 |
|-----------|-------|------|
| `replay`  | 8000  | 索引/回放服务（FastAPI + uvicorn）。校验并导入 WARC、保存内存索引、按固定时点选取记录、清洗重写 HTML、回放 PNG。 |
| `viewer`  | 8080  | 纯静态查看器页面（nginx）。选择时点与原 URI、展示来源信息，用空 token 的 `sandbox` iframe 承载回放文档。 |

查看器仅通过 `http://localhost:8000` 的 CORS 白名单接口与回放服务通信；
回放文档由 `frame-ancestors` 限定只能被查看器嵌入。

## 导入约束（后端强制校验）

- 未压缩 **WARC/1.1**；gzip 魔数直接拒绝；独立做分帧扫描，逐条与成熟库
  `warcio` 交叉核对。
- 仅 **response** 记录；不做重定向（只接受 HTTP 200）、不接受 revisit、
  不接受 `Transfer-Encoding: chunked`、不接受 `Content-Encoding`。
- WARC 层校验：`Content-Length` 字节数与物理分帧一致；单一强制头
  （`WARC-Record-ID` 为 `<urn:uuid:…>` 且全归档唯一、`WARC-Target-URI`
  为绝对 http/https 且无 fragment、`WARC-Date` 为 `YYYY-MM-DDTHH:MM:SSZ`）。
- HTTP 层校验：状态行、单一 HTTP `Content-Length` 且等于实体字节数。
- 内容只接受：
  - `text/html` 且显式声明 `charset=utf-8`，实体必须能严格 UTF-8 解码；
  - `image/png`，实体必须以 PNG 签名开头。
- 批量上限：**最多 10 条记录、未压缩载荷合计 ≤ 64 KiB**；整批原子导入，
  超限或冲突时一条都不落库。
- **同一 URI、同一 UTC 时刻的重复抓取一律拒绝**（入库时与批次内均检查）。

## 时点选取与链接重写

- 选取规则：`max(date) where date <= cutoff`；同一时刻重复已在导入时拒绝，
  因此结果唯一。截止时刻早于首次抓取即为缺口。
- HTML 中的相对链接/图片：先按**归档文档 URI** 与文档中**第一个合法
  `<base href>`**（必须解析到同主机 http/https，跨主机 base 被忽略）解析，
  再映射到回放服务上同一截止时刻的 `/replay?at=…&uri=…`。
- 映射规则：`<a>` 只能指向该时点存在的 HTML 记录；`<img>` 只能指向该时点
  存在的 PNG 记录。查询串是 URI 身份的一部分，fragment 不参与。
- 缺失、非 http(s) 方案（`javascript:`/`data:`/`mailto:` 等）、不支持的
  内容 → 链接变成不可点击的 `[link unavailable in archive]`，图片变成
  `[archived image missing: …]`，**不产生任何网络请求**。

## 安全边界

- **标签与属性白名单**（BeautifulSoup 解析，策略在本项目代码中）：保留文本、
  普通链接、表格、PNG；`script/noscript/style/template/iframe/object/embed/
  applet/frame/frameset/link/meta/base/svg/math` 连内容一起删除；
  `form`、事件属性（`on*`）、`style`、`srcset`、`target` 等全部剥离；
  输出会再次解析做结构化校验，禁止用正则猜内容。
- iframe：`<iframe sandbox="">`（无 allow-scripts、无 allow-same-origin、
  无 allow-forms、无 allow-top-navigation）。
- 回放响应 CSP：
  `default-src 'none'; img-src 'self'; style-src 'unsafe-inline';
  base-uri 'none'; form-action 'none'; sandbox`，
  即图片只可能来自回放服务本身，归档文档连内联脚本都无法执行。
- 另带 `X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`、
  `Cross-Origin-Resource-Policy: same-site`；`Cache-Control: no-store`。
- 回放服务无任何出站 HTTP 客户端代码；选择与解析全部在本地完成。

## 本地运行

```bash
docker compose up --build
# 查看器:        http://localhost:8080
# 回放服务 API:  http://localhost:8000
```

不使用 Docker 时：

```bash
pip install -r requirements.txt
uvicorn app.main:app --port 8000           # 回放服务
cd viewer && python3 -m http.server 8080   # 静态查看器（页面默认 API 即 :8000）
```

打开 http://localhost:8080，导入未压缩 WARC/1.1 文件，选择原 URI 与
截止时刻即可。回放页顶部与 iframe 文档内都会显示实际命中的
Record-ID / 抓取时刻 / 原 URI。

### 主要 API

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/import` | 原始 WARC/1.1 字节（`application/warc`） |
| POST | `/api/reset`  | 清空内存归档 |
| GET  | `/api/stats`  | 记录数/字节数与上限 |
| GET  | `/api/uris`   | 按 URI 分组的全部抓取时刻 |
| GET  | `/api/select?uri=…&at=…` | 预览时点选取结果（不返回正文） |
| GET  | `/replay?at=…&uri=…`     | 固定时点回放（清洗 HTML 或 PNG），命中信息在 `X-Archive-*` 响应头 |

## 测试

```bash
pip install pytest pytest-asyncio httpx playwright
python3 -m playwright install chromium
python3 -m pytest
```

- `test_warc_validation.py` — 分帧/长度/ID/URI/日期/内容类型/gzip/chunked/
  302/revisit/10 条与 64 KiB 上限。
- `test_two_crawls.py` — 两次抓取下「不晚于截止时刻的最新记录」选取、
  来源响应头、同 URI 同时刻重复拒绝且整批原子。
- `test_relative.py` — 相对路径、`../`、绝对路径、首个合法 `<base>`、
  非法跨主机 base 被忽略、缺口渲染。
- `test_sanitize.py` — 恶意 HTML（脚本/事件/样式/表单/嵌入/svg/data:/
  javascript:）清洗，安全 PNG 重写后确实取回归档字节。
- `test_browser_flow.py` — 真实 Chromium 流程：导入 → 选时点/URI →
  sandbox iframe 展示 → 在帧内点重写链接跳到另一张存档页；同时启动一个
  金丝雀 HTTP 源充当「原网站」，用 Playwright 路由拦截 + 服务端命中计数
  双重证明：**除两个本地服务外没有任何请求，金丝雀零命中**；并校验回放
  CSP 中 `img-src 'self'`。
