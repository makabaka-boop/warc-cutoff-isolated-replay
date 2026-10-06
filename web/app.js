// Control page for the restricted WARC replayer.
// This is the ONLY script-bearing origin; the replay frame is sandbox="" and
// runs no scripts at all.
const REPLAY_ORIGIN =
  window.location.origin.indexOf("8080") !== -1
    ? window.location.origin.replace("8080", "8000")
    : "http://localhost:8000";

const $ = (id) => document.getElementById(id);
const frame = $("frame");
const uriSel = $("uri");

function cutoffZ() {
  // datetime-local is interpreted explicitly as UTC.
  let v = $("cutoff").value || "";
  if (v.length === 16) v += ":00"; // HH:MM -> HH:MM:SS
  return v + "Z";
}

async function loadIndex() {
  const res = await fetch(REPLAY_ORIGIN + "/api/index", { cache: "no-store" });
  const data = await res.json();
  uriSel.innerHTML = "";
  if (!data.uris || !data.uris.length) {
    uriSel.innerHTML = '<option value="">（归档为空）</option>';
    return data;
  }
  for (const item of data.uris) {
    const o = document.createElement("option");
    o.value = item.uri;
    const latest = item.captures[item.captures.length - 1];
    o.textContent = item.uri + "  (" + item.captures.length + " 次抓取, 最新 " + latest + ")";
    uriSel.appendChild(o);
  }
  return data;
}

async function showSelection(uri, cutoff) {
  const url =
    REPLAY_ORIGIN + "/api/select?cutoff=" +
    encodeURIComponent(cutoff) + "&uri=" + encodeURIComponent(uri);
  const res = await fetch(url, { cache: "no-store" });
  const data = await res.json();
  if (res.status === 200) {
    $("m-rec").textContent = data.record_id;
    $("m-date").textContent = data.captured_at;
    $("m-uri").textContent = data.canonical_uri;
    $("m-type").textContent = data.content_type;
    $("m-state").innerHTML =
      '<span class="badge ok">命中本地归档</span>';
    $("frame-meta").textContent =
      "记录 " + data.record_id + "，抓取于 " + data.captured_at +
      "（不晚于截止 " + data.cutoff + "）";
  } else {
    $("m-rec").textContent = "—";
    $("m-date").textContent = data.cutoff || "—";
    $("m-uri").textContent = data.canonical_uri || uri;
    $("m-type").textContent = "—";
    $("m-state").innerHTML =
      '<span class="badge gap">缺口：未回源</span>';
    $("frame-meta").textContent =
      "内容缺口：" + (data.reason || "该时点无记录") + "。回放器不会联系线上站点。";
  }
  return data;
}

$("go").addEventListener("click", async () => {
  const uri = uriSel.value;
  if (!uri) return;
  const cutoff = cutoffZ();
  const view =
    REPLAY_ORIGIN + "/view/" + encodeURIComponent(cutoff) + "/" + uri;
  frame.src = view;
  await showSelection(uri, cutoff);
});

$("upload").addEventListener("click", async () => {
  const f = $("warcfile").files[0];
  const msg = $("uploadmsg");
  if (!f) { msg.textContent = "先选择 .warc 文件"; return; }
  if (f.size > 64 * 1024) { msg.textContent = "超过 64 KiB，拒绝"; return; }
  const buf = await f.arrayBuffer();
  const res = await fetch(REPLAY_ORIGIN + "/api/import", {
    method: "POST",
    headers: { "content-type": "application/warc" },
    body: buf,
  });
  const data = await res.json();
  if (!res.ok) {
    msg.style.color = "#9a2b2b";
    msg.textContent = "拒绝导入：" + (data.error || res.status);
    return;
  }
  msg.style.color = "#1e6b35";
  msg.textContent =
    "已导入 " + data.record_count + " 条记录，覆盖 " + data.uris.length + " 个 URI。";
  await loadIndex();
});

loadIndex().catch((e) => {
  uriSel.innerHTML = '<option value="">（无法连接回放服务）</option>';
  console.error(e);
});
