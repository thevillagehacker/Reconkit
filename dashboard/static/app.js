/* RECONKIT dashboard — OUTPUT / PROMPT (scans stay on the CLI) */

const state = {
  view: "output",
  target: "",
  phase: "",
  tool: "",
  fileQ: "",
  files: [],
  filePath: "",
  fileContent: "",
  pollTimer: null,
  fingerprint: "",
};

const $ = (id) => document.getElementById(id);

async function api(path, opts = {}) {
  const res = await fetch(path, {
    cache: "no-store",
    headers: { Accept: "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function setView(name) {
  state.view = name;
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll(".btab").forEach((b) => b.classList.remove("active"));
  const map = { output: "viewOutput", prompt: "viewPrompt" };
  const el = $(map[name]);
  if (el) el.classList.add("active");
  const tab = document.querySelector(`.btab[data-view="${name}"]`);
  if (tab) tab.classList.add("active");
  if (name === "output") loadOutputs();
  if (name === "prompt") loadLlm();
}

async function loadTargets() {
  const data = await api("/api/targets");
  const list = data.targets || data || [];
  const ul = $("targetList");
  ul.innerHTML = "";
  const q = ($("targetSearch").value || "").toLowerCase();
  let n = 0;
  for (const t of list) {
    const name = t.target || t.name || t;
    if (q && !String(name).toLowerCase().includes(q)) continue;
    n++;
    const li = document.createElement("li");
    if (state.target === name) li.classList.add("active");
    const count = t.finding_count ?? "";
    li.innerHTML = `<span>${esc(name)}</span><span class="meta">${count}</span>`;
    li.onclick = () => {
      state.target = name;
      if ($("missionBanner")) $("missionBanner").textContent = name;
      $("btnAllTargets").classList.remove("active");
      loadTargets();
      refreshAll();
    };
    ul.appendChild(li);
  }
  $("targetCount").textContent = `${n} target(s)`;
  if (!state.target) $("btnAllTargets").classList.add("active");
}

function fillSelect(id, values, current) {
  const sel = $(id);
  if (!sel) return;
  const keep = current || "";
  sel.innerHTML = `<option value="">all</option>` + values.map((v) =>
    `<option value="${esc(v)}" ${v === keep ? "selected" : ""}>${esc(v)}</option>`
  ).join("");
}

function rawHref(target, rel) {
  const t = encodeURIComponent(target || "");
  const p = String(rel || "")
    .replace(/\\/g, "/")
    .split("/")
    .filter((seg) => seg && seg !== "..")
    .map(encodeURIComponent)
    .join("/");
  return `/raw/${t}/${p}`;
}

function fmtBytes(n) {
  const x = Number(n) || 0;
  if (x < 1024) return `${x} B`;
  if (x < 1024 * 1024) return `${(x / 1024).toFixed(1)} KB`;
  return `${(x / (1024 * 1024)).toFixed(1)} MB`;
}

function setRawLink(href, visible) {
  const a = $("rawLink");
  if (!a) return;
  if (visible && href) {
    a.href = href;
    a.hidden = false;
  } else {
    a.removeAttribute("href");
    a.hidden = true;
  }
}

function showTooLarge(data, href) {
  const pre = $("filePreview");
  pre.textContent = "";
  const size = fmtBytes(data.size);
  pre.appendChild(document.createTextNode(
    `This file is too large to display (${size}).\n\n`
  ));
  const a = document.createElement("a");
  a.href = href;
  a.className = "raw-link";
  a.target = "_blank";
  a.rel = "noopener";
  a.textContent = "View raw";
  pre.appendChild(a);
  const cap = 50 * 1024 * 1024;
  if (Number(data.size) > cap) {
    pre.appendChild(document.createTextNode(
      "\n\nBrowser raw view is capped at 50 MB. Open the file on disk instead."
    ));
  }
  if (data.disk_path) {
    pre.appendChild(document.createTextNode("\n\nOn disk:\n"));
    const disk = document.createElement("span");
    disk.className = "disk-path";
    disk.textContent = data.disk_path;
    pre.appendChild(disk);
  }
}

async function loadOutputs() {
  if (!state.target) {
    $("fileBody").innerHTML = `<tr><td colspan="4" class="muted">Select a target</td></tr>`;
    $("filePreview").textContent = "Select a target in the left list.";
    $("fileCount").textContent = "0";
    setRawLink("", false);
    if ($("previewPath")) $("previewPath").textContent = "select a file";
    return;
  }
  const data = await api(`/api/outputs?target=${encodeURIComponent(state.target)}`);
  state.files = data.files || [];
  fillSelect("fltPhase", data.phases || [], state.phase);
  fillSelect("fltTool", data.tools || [], state.tool);
  renderFileList();
}

function renderFileList() {
  const q = (state.fileQ || "").toLowerCase();
  const rows = (state.files || []).filter((f) => {
    if (state.phase && f.phase !== state.phase) return false;
    if (state.tool && f.tool !== state.tool) return false;
    if (q && !String(f.path || "").toLowerCase().includes(q) && !String(f.name || "").toLowerCase().includes(q)) {
      return false;
    }
    return true;
  });
  $("fileCount").textContent = String(rows.length);
  $("fileBody").innerHTML = rows.map((f) => `
    <tr data-path="${esc(f.path)}" class="${f.path === state.filePath ? "active" : ""}">
      <td>${esc(f.phase)}</td>
      <td>${esc(f.tool)}</td>
      <td>${esc(f.path)}</td>
      <td>${esc(f.lines)}</td>
    </tr>
  `).join("") || `<tr><td colspan="4" class="muted">No files yet — run a scan</td></tr>`;
  $("fileBody").querySelectorAll("tr[data-path]").forEach((tr) => {
    tr.onclick = () => openFile(tr.dataset.path);
  });
}

async function openFile(rel) {
  if (!state.target || !rel) return;
  state.filePath = rel;
  renderFileList();
  $("previewPath").textContent = rel;
  const fallbackRaw = rawHref(state.target, rel);
  setRawLink(fallbackRaw, true);
  try {
    const res = await fetch(
      `/api/file?target=${encodeURIComponent(state.target)}&path=${encodeURIComponent(rel)}`,
      { cache: "no-store", headers: { Accept: "application/json" } }
    );
    const data = await res.json().catch(() => ({ error: res.statusText }));
    const href = data.raw_url || fallbackRaw;
    setRawLink(href, true);
    if (data.too_large) {
      state.fileContent = "";
      showTooLarge(data, href);
      return;
    }
    if (!res.ok) {
      state.fileContent = "";
      const msg = data.error || res.statusText || "failed to load file";
      $("filePreview").textContent = msg + (href ? `\n\nView raw: ${href}` : "");
      return;
    }
    state.fileContent = data.content || "";
    let text = state.fileContent || "(empty)";
    if (data.truncated) {
      text += "\n\n— truncated; open View raw for the full file —";
    }
    $("filePreview").textContent = text;
  } catch (e) {
    $("filePreview").textContent = String(e.message || e);
  }
}

async function loadLlm() {
  try {
    const st = await api("/api/llm");
    $("llmChip").textContent = st.ok
      ? `${st.provider || "?"} · ${st.model || "?"}`
      : (st.error || "not configured");
  } catch (e) {
    $("llmChip").textContent = String(e.message || e);
  }
}

async function sendPrompt() {
  const prompt = ($("promptText").value || "").trim();
  if (!prompt) {
    $("promptReply").textContent = "Type a prompt first.";
    return;
  }
  const attach = $("chkAttach") && $("chkAttach").checked;
  $("promptReply").textContent = "…";
  $("btnSendPrompt").disabled = true;
  try {
    const data = await api("/api/prompt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        prompt,
        target: state.target || "",
        path: attach ? (state.filePath || "") : "",
      }),
    });
    if (!data.ok) {
      $("promptReply").textContent = data.error || "request failed";
      return;
    }
    $("llmChip").textContent = `${data.provider || "?"} · ${data.model || "?"}`;
    $("promptReply").textContent = data.reply || "(empty reply)";
  } catch (e) {
    $("promptReply").textContent = String(e.message || e);
  } finally {
    $("btnSendPrompt").disabled = false;
  }
}

async function pollStatus() {
  try {
    const st = await api("/api/status");
    const fp = st.disk_fingerprint || st.memory_fingerprint || "";
    if (state.fingerprint && fp && fp !== state.fingerprint) {
      state.fingerprint = fp;
      if (state.view === "output") await loadOutputs();
    } else if (!state.fingerprint) {
      state.fingerprint = fp;
    }
    $("footerStatus").textContent = "dashboard";
  } catch (_) { /* ignore */ }
}

function startPoll() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(pollStatus, 5000);
  pollStatus();
}

async function refreshAll() {
  await loadTargets();
  if (state.view === "output") await loadOutputs();
  else if (state.view === "prompt") await loadLlm();
}

function wire() {
  document.querySelectorAll(".btab").forEach((b) => {
    b.onclick = () => setView(b.dataset.view);
  });
  $("btnAllTargets").onclick = () => {
    state.target = "";
    if ($("missionBanner")) $("missionBanner").textContent = "CLI output viewer";
    loadTargets();
    refreshAll();
  };
  $("targetSearch").oninput = () => loadTargets();
  $("btnRefresh").onclick = () => refreshAll();
  $("btnOutputApply").onclick = () => {
    state.phase = $("fltPhase").value;
    state.tool = $("fltTool").value;
    state.fileQ = $("fltFileQ").value;
    renderFileList();
  };
  $("btnAskFile").onclick = () => {
    if (!state.filePath) {
      alert("Open a file in OUTPUT first.");
      return;
    }
    setView("prompt");
    $("chkAttach").checked = true;
    if (!$("promptText").value) {
      $("promptText").value = `Summarize this recon file and flag anything worth /prove or manual review. Stay in-scope.`;
    }
  };
  $("btnSendPrompt").onclick = () => sendPrompt();
}

document.addEventListener("DOMContentLoaded", async () => {
  wire();
  await refreshAll();
  startPoll();
  setView("output");
});
