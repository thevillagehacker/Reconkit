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
  prevSizes: {},
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
    li.innerHTML = `<span>${esc(name)}</span>`;
    li.onclick = () => {
      state.target = name;
      state.filePath = "";
      state.fileContent = "";
      setRawLink("", false);
      if ($("missionBanner")) $("missionBanner").textContent = name;
      if ($("previewPath")) $("previewPath").textContent = "select a file";
      if ($("filePreview")) {
        $("filePreview").textContent = "Select a file from the list.";
      }
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
  const now = Date.now() / 1000;
  $("fileBody").innerHTML = rows.map((f) => {
    const prev = state.prevSizes[f.path];
    const writing = prev != null && Number(f.size) > Number(prev);
    const fresh = now - Number(f.mtime || 0) < 20;
    const cls = [
      f.path === state.filePath ? "active" : "",
      writing || fresh ? "writing" : "",
    ].filter(Boolean).join(" ");
    return `
    <tr data-path="${esc(f.path)}" class="${cls}">
      <td>${esc(f.phase)}</td>
      <td>${esc(f.tool)}</td>
      <td>${esc(f.path)}</td>
      <td>${Number(f.lines) > 0 ? esc(f.lines) : esc(fmtBytes(f.size))}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="4" class="muted">No files yet — run a scan</td></tr>`;
  renderTape(now);
  const next = {};
  for (const f of state.files || []) next[f.path] = f.size;
  state.prevSizes = next;
  $("fileBody").querySelectorAll("tr[data-path]").forEach((tr) => {
    tr.onclick = () => openFile(tr.dataset.path);
  });
}

function renderTape(now) {
  const el = $("liveTape");
  if (!el) return;
  const rows = (state.files || [])
    .filter((f) => {
      const p = String(f.path || "");
      return p.startsWith("tools/") || p.endsWith(".txt") || p.startsWith("nuclei_");
    })
    .filter((f) => now - Number(f.mtime || 0) < 120)
    .sort((a, b) => Number(b.mtime) - Number(a.mtime))
    .slice(0, 8);
  if (!rows.length) {
    el.textContent = "Live tool files show up here while a scan is writing.";
    return;
  }
  el.textContent = "";
  rows.forEach((f) => {
    const prev = state.prevSizes[f.path];
    const writing = prev != null && Number(f.size) > Number(prev);
    const line = document.createElement("div");
    line.className = writing ? "live" : "";
    const age = Math.max(0, Math.round(now - Number(f.mtime || now)));
    line.textContent = `${writing ? "writing" : "wrote"}  ${f.path}  ${fmtBytes(f.size)}  ${age}s ago`;
    el.appendChild(line);
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

function filePhase() {
  const hit = (state.files || []).find((f) => f.path === state.filePath);
  return (hit && hit.phase) || state.phase || "";
}

async function sendPrompt() {
  const prompt = ($("promptText").value || "").trim();
  if (!prompt) {
    $("promptReply").textContent = "Type a prompt first.";
    return;
  }
  const usePhase = $("chkPhase") && $("chkPhase").checked;
  const attach = $("chkAttach") && $("chkAttach").checked && !usePhase;
  const phase = usePhase ? filePhase() : "";
  if (usePhase && (!state.target || !phase)) {
    $("promptReply").textContent = "Select a phase filter, or open a file, so the phase is known.";
    return;
  }
  if (attach && (!state.target || !state.filePath)) {
    $("promptReply").textContent = "Open a file in OUTPUT first, or uncheck attach.";
    return;
  }
  $("promptReply").textContent = "";
  $("btnSendPrompt").disabled = true;
  try {
    const res = await fetch("/api/prompt", {
      method: "POST",
      cache: "no-store",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
      body: JSON.stringify({
        prompt,
        stream: true,
        target: state.target || "",
        path: attach ? (state.filePath || "") : "",
        phase: phase || "",
      }),
    });
    const ctype = res.headers.get("content-type") || "";
    if (!ctype.includes("text/event-stream")) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      $("promptReply").textContent = data.error || data.reply || "request failed";
      return;
    }
    const reader = res.body && res.body.getReader ? res.body.getReader() : null;
    if (!reader) {
      $("promptReply").textContent = await res.text();
      return;
    }
    const decoder = new TextDecoder();
    let buf = "";
    let reply = "";
    while (true) {
      const step = await reader.read();
      if (step.done) break;
      buf += decoder.decode(step.value, { stream: true });
      const chunks = buf.split("\n\n");
      buf = chunks.pop() || "";
      for (const chunk of chunks) {
        const line = chunk.split("\n").find((ln) => ln.startsWith("data:"));
        if (!line) continue;
        let ev;
        try {
          ev = JSON.parse(line.slice(5).trim());
        } catch (_) {
          continue;
        }
        if (ev.error) {
          $("promptReply").textContent = (reply ? reply + "\n\n" : "") + ev.error;
          return;
        }
        if (ev.meta) {
          $("llmChip").textContent = `${ev.meta.provider || "?"} · ${ev.meta.model || "?"}`;
        }
        if (ev.delta) {
          reply += ev.delta;
          $("promptReply").textContent = reply;
        }
      }
    }
    if (!reply) $("promptReply").textContent = "(empty reply)";
  } catch (e) {
    $("promptReply").textContent = String(e.message || e);
  } finally {
    $("btnSendPrompt").disabled = false;
  }
}

async function searchContent() {
  const q = ($("fltContentQ").value || "").trim();
  if (!state.target) {
    $("filePreview").textContent = "Select a target first.";
    return;
  }
  if (q.length < 2) {
    $("filePreview").textContent = "Type at least 2 characters to search inside files.";
    return;
  }
  const data = await api(
    `/api/search?target=${encodeURIComponent(state.target)}&q=${encodeURIComponent(q)}`
  );
  const pre = $("filePreview");
  pre.textContent = "";
  const hits = data.hits || [];
  if (!hits.length) {
    pre.textContent = data.error || `No lines contain “${q}”.`;
    return;
  }
  pre.appendChild(document.createTextNode(
    `${hits.length} hit(s)${data.truncated ? " (capped)" : ""}\n\n`
  ));
  hits.forEach((h) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "search-hit";
    btn.textContent = `${h.path}:${h.line}  ${h.text}`;
    btn.onclick = () => openFile(h.path);
    pre.appendChild(btn);
    pre.appendChild(document.createTextNode("\n"));
  });
}

async function diffOpenFile() {
  if (!state.target || !state.filePath) {
    $("filePreview").textContent = "Open subdomains.txt, alive.txt, or urls.txt first.";
    return;
  }
  const name = state.filePath.split("/").pop();
  const data = await api(
    `/api/diff?target=${encodeURIComponent(state.target)}&file=${encodeURIComponent(name)}`
  );
  if (!data.ok) {
    $("filePreview").textContent = data.error || "diff failed";
    return;
  }
  const lines = [
    `${name}: ${data.new_count} new, ${data.gone_count} gone`,
    data.has_prev ? "compared with the previous run" : "no previous run saved yet — run the stage again to build a diff",
    "",
    "# new",
    ...(data.new || []),
    "",
    "# gone",
    ...(data.gone || []),
  ];
  $("filePreview").textContent = lines.join("\n");
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
    state.filePath = "";
    state.fileContent = "";
    setRawLink("", false);
    if ($("missionBanner")) $("missionBanner").textContent = "CLI output viewer";
    if ($("previewPath")) $("previewPath").textContent = "select a file";
    loadTargets();
    refreshAll();
  };
  $("targetSearch").oninput = () => loadTargets();
  $("btnRefresh").onclick = () => refreshAll();
  const applyFileFilters = () => {
    state.phase = $("fltPhase").value;
    state.tool = $("fltTool").value;
    state.fileQ = $("fltFileQ").value;
    renderFileList();
  };
  $("btnOutputApply").onclick = applyFileFilters;
  $("fltPhase").onchange = applyFileFilters;
  $("fltTool").onchange = applyFileFilters;
  $("fltFileQ").oninput = applyFileFilters;
  $("btnContentSearch").onclick = () => searchContent().catch((e) => {
    $("filePreview").textContent = String(e.message || e);
  });
  $("fltContentQ").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      searchContent().catch((e) => {
        $("filePreview").textContent = String(e.message || e);
      });
    }
  });
  $("btnDiffFile").onclick = () => diffOpenFile().catch((e) => {
    $("filePreview").textContent = String(e.message || e);
  });
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
});
