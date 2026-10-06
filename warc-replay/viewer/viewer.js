"use strict";

/* Viewer control plane.  It talks only to the replay service declared in
   the page; the archived documents themselves run in a sandboxed iframe
   with no script and no same-origin rights. */

const API_BASE =
  new URLSearchParams(location.search).get("api") ||
  document
    .querySelector('meta[name="api-base"]')
    .getAttribute("content");

const $ = (id) => document.getElementById(id);
const frame = $("replay-frame");
const resultBox = $("import-result");

function showResult(obj, isError = false) {
  resultBox.textContent = JSON.stringify(obj, null, 2);
  resultBox.style.color = isError ? "#ffb4ab" : "#cfe0ff";
}

async function api(path, options = {}) {
  const resp = await fetch(API_BASE + path, {
    method: options.method || "GET",
    headers: options.body ? { "content-type": "application/warc" } : undefined,
    body: options.body,
  });
  let payload = null;
  try {
    payload = await resp.json();
  } catch (_e) {
    payload = { error: `non-JSON response (${resp.status})` };
  }
  if (!resp.ok) {
    const err = new Error(payload && payload.error ? payload.error : resp.statusText);
    err.payload = payload;
    throw err;
  }
  return payload;
}

async function refresh() {
  const [stats, uris] = await Promise.all([
    api("/api/stats"),
    api("/api/uris"),
  ]);
  $("stat-count").textContent = `${stats.records} / ${stats.max_records}`;
  $("stat-bytes").textContent =
    `${stats.total_bytes.toLocaleString()} / ${stats.max_total_bytes.toLocaleString()} 字节`;

  const view = $("records-view");
  const select = $("uri-select");
  select.innerHTML = "";
  if (!uris.length) {
    view.innerHTML = '<p class="hint">尚未导入。</p>';
    const opt = document.createElement("option");
    opt.textContent = "（无）";
    opt.value = "";
    select.appendChild(opt);
    return;
  }
  view.innerHTML = "";
  for (const entry of uris) {
    const block = document.createElement("div");
    block.className = "uri-block";
    const isPng = entry.captures.every((c) => c.content_type === "image/png");
    block.innerHTML =
      `<code></code><span class="badge ${isPng ? "png" : ""}">` +
      (isPng ? "PNG" : "HTML") +
      ` · ${entry.captures.length} 次抓取</span>` +
      `<ul>${entry.captures
        .map((c) => `<li>${c.date} — <code>${c.record_id}</code></li>`)
        .join("")}</ul>`;
    block.querySelector("code").textContent = entry.uri;
    view.appendChild(block);

    const opt = document.createElement("option");
    opt.value = entry.uri;
    opt.textContent = entry.uri;
    select.appendChild(opt);
  }
}

$("import-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const file = $("warc-file").files[0];
  if (!file) return;
  try {
    const buf = await file.arrayBuffer();
    const outcome = await api("/api/import", {
      method: "POST",
      body: buf,
    });
    showResult(outcome);
    await refresh();
  } catch (err) {
    showResult(err.payload || { error: err.message }, true);
  }
});

$("reset-btn").addEventListener("click", async () => {
  await api("/api/reset", { method: "POST" });
  resultBox.textContent = "";
  frame.src = "about:blank";
  $("source-card").classList.add("hidden");
  await refresh();
});

$("replay-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const uri = $("uri-select").value;
  const at = $("instant-input").value.trim();
  if (!uri || !at) return;

  const card = $("source-card");
  card.classList.remove("hidden");
  $("src-uri").textContent = uri;
  $("src-cutoff").textContent = at;
  $("src-gap").classList.add("hidden");

  let selection;
  try {
    selection = await api(
      `/api/select?uri=${encodeURIComponent(uri)}&at=${encodeURIComponent(at)}`
    );
  } catch (err) {
    $("src-date").textContent = "—";
    $("src-id").textContent = "—";
    $("src-ct").textContent = "—";
    $("src-len").textContent = "—";
    const gap = $("src-gap");
    gap.textContent =
      "缺口：该 URI 在截止时刻之前没有任何本地记录（或不支持的内容/协议）；不会回源。" +
      (err.message ? ` （${err.message}）` : "");
    gap.classList.remove("hidden");
    frame.src = "about:blank";
    return;
  }

  const r = selection.record;
  $("src-date").textContent = r.date;
  $("src-id").textContent = r.record_id;
  $("src-ct").textContent = r.content_type;
  $("src-len").textContent = `${r.length} 字节`;

  const replayUrl =
    API_BASE +
    `/replay?at=${encodeURIComponent(at)}&uri=${encodeURIComponent(uri)}`;
  frame.src = replayUrl;
});

refresh().catch((err) => showResult({ error: err.message }, true));
