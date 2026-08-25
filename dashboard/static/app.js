/* RECONKIT dashboard — no animations, no force-layout, poll only when needed */

const state = {
  view: "mission",
  target: "",
  module: "",
  severity: "",
  type: "",
  notable: "",
  confidence: "C1",
  q: "",
  limit: 80,
  offset: 0,
  total: 0,
  proofStatus: "",
  graphMinScore: 40,
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

function stripAnsi(s) {
  return String(s ?? "")
    .replace(/\u001b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, "")
    .replace(/\[(?:\d{1,3};){0,8}\d{1,3}m/g, "")
    .replace(/[ \t]{2,}/g, " ");
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function sevClass(s) {
  return `sev sev-${(s || "unknown").toLowerCase()}`;
}

function setView(name) {
  state.view = name;
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll(".btab").forEach((b) => b.classList.remove("active"));
  const map = {
    mission: "viewMission",
    recon: "viewRecon",
    inbox: "viewInbox",
    proofs: "viewProofs",
    graph: "viewGraph",
    insights: "viewInsights",
  };
  const el = $(map[name]);
  if (el) el.classList.add("active");
  const tab = document.querySelector(`.btab[data-view="${name}"]`);
  if (tab) tab.classList.add("active");
  if (name === "mission") loadMission();
  if (name === "recon") loadRecon();
  if (name === "inbox") loadInbox();
  if (name === "proofs") loadProofs();
  if (name === "graph") loadGraph();
  if (name === "insights") loadInsights();
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
    const count = t.finding_count ?? t.record_count ?? t.count ?? "";
    if (q && !String(name).toLowerCase().includes(q)) continue;
    n++;
    const li = document.createElement("li");
    if (state.target === name) li.classList.add("active");
    li.innerHTML = `<span>${esc(name)}</span><span class="meta">${count}</span>`;
    li.onclick = () => {
      state.target = name;
      $("btnAllTargets").classList.remove("active");
      loadTargets();
      refreshAll();
    };
    ul.appendChild(li);
  }
  $("targetCount").textContent = `${n} target(s)`;
  if (!state.target) $("btnAllTargets").classList.add("active");
}

async function loadMission() {
  const q = new URLSearchParams();
  if (state.target) q.set("target", state.target);
  q.set("mode", "live");
  const m = await api(`/api/scan?${q}`);
  const s = m.summary || {};
  const st = (m.status || "idle").toUpperCase();
  const active = !!m.active;
  if ($("missionBanner")) {
    $("missionBanner").textContent = active
      ? `${st} · ${m.current_module || "…"}`
      : `${st}`;
  }
  if ($("liveStatusLabel")) $("liveStatusLabel").textContent = st;
  if ($("liveMessage")) $("liveMessage").textContent = m.message || m.current_tool || "—";
  if ($("livePhaseFrac")) {
    $("livePhaseFrac").textContent = `${s.phases_complete ?? 0} / ${s.phases_total ?? 0}`;
  }
  if ($("liveElapsed")) $("liveElapsed").textContent = `${s.elapsed_s ?? 0}s`;
  if ($("liveProgressBar")) {
    $("liveProgressBar").style.width = `${Math.min(100, s.pct ?? 0)}%`;
  }
  const pill = $("alertPill");
  if (pill) {
    pill.className = "alert-pill " + (active ? "yellow" : "green");
    pill.textContent = active ? "SCAN" : "IDLE";
  }
  const tiles = m.tiles || [];
  const body = $("phaseTiles");
  if (body) {
    body.innerHTML = tiles.map((t) => `
      <tr>
        <td>${esc(t.status || "")}</td>
        <td>${esc(t.id || t.ship || "")}</td>
        <td>${esc(t.signals ?? 0)}</td>
      </tr>
    `).join("") || `<tr><td colspan="3" class="muted">No scan yet — pick a target and Quick scan, or /run</td></tr>`;
  }
  if ($("phaseTilesChip")) {
    $("phaseTilesChip").textContent = `${tiles.length} module(s)`;
  }
}

async function loadRecon() {
  const params = new URLSearchParams();
  if (state.target) params.set("target", state.target);
  if (state.module) params.set("module", state.module);
  if (state.severity) params.set("severity", state.severity);
  if (state.type) params.set("type", state.type);
  if (state.notable) params.set("notable", state.notable);
  if (state.q) params.set("q", state.q);
  if (state.confidence) params.set("min_confidence", state.confidence);
  params.set("limit", String(state.limit));
  params.set("offset", String(state.offset));
  const [ov, rec] = await Promise.all([
    api(`/api/overview?${params}`),
    api(`/api/records?${params}`),
  ]);
  $("kpiFindings").textContent = ov.record_count ?? ov.finding_count ?? "—";
  $("kpiTargets").textContent = ov.target_count ?? "—";
  $("kpiCrit").textContent = (ov.by_severity || {}).critical ?? 0;
  $("kpiHigh").textContent = (ov.by_severity || {}).high ?? 0;
  $("kpiMed").textContent = (ov.by_severity || {}).medium ?? 0;
  $("kpiProofsMini").textContent = ov.proof_confirmed ?? ov.proof_count ?? 0;
  $("activeTargetChip").textContent = state.target || "all targets";
  $("programBadge").textContent = `program: ${ov.program || "default"}`;
  const mods = Object.keys(ov.by_module || {}).sort();
  const sel = $("fltModule");
  const cur = state.module;
  sel.innerHTML = `<option value="">all</option>` + mods.map((m) =>
    `<option value="${esc(m)}" ${m === cur ? "selected" : ""}>${esc(m)}</option>`
  ).join("");
  const rows = rec.records || rec.findings || [];
  state.total = rec.total ?? rows.length;
  const fb = rec.filters && rec.filters.confidence_fallback;
  $("reconPageInfo").textContent = `${state.offset + 1}–${state.offset + rows.length} / ${state.total}`
    + (fb ? ` · showing ${fb} inventory (no C1+)` : "");
  $("findingsBody").innerHTML = rows.map((r) => `
    <tr data-id="${esc(r.id)}">
      <td><span class="${sevClass(r.severity)}">${esc(r.severity)}</span></td>
      <td>${esc(r.confidence || "C0")}</td>
      <td>${esc(r.module)}</td>
      <td>${esc(r.ftype)}</td>
      <td>${esc(stripAnsi(r.title))}</td>
      <td>${esc(stripAnsi(r.asset))}</td>
      <td>${esc(r.score)}</td>
    </tr>
  `).join("");
  $("findingsBody").querySelectorAll("tr").forEach((tr) => {
    tr.onclick = () => {
      const r = rows.find((x) => x.id === tr.dataset.id);
      if (!r) return;
      $("detailBody").innerHTML = `
        <h3>${esc(stripAnsi(r.title))}</h3>
        <div class="kv">
          <div class="k">Module</div><div>${esc(r.module)}</div>
          <div class="k">Severity</div><div><span class="${sevClass(r.severity)}">${esc(r.severity)}</span></div>
          <div class="k">Asset</div><div>${esc(stripAnsi(r.asset))}</div>
          <div class="k">Score</div><div>${esc(r.score)}</div>
        </div>
        <pre>${esc(stripAnsi(r.evidence || ""))}</pre>
      `;
    };
  });
}

async function loadInbox() {
  const params = new URLSearchParams();
  if (state.target) params.set("target", state.target);
  params.set("limit", "50");
  try {
    const data = await api(`/api/inbox?${params}`);
    const rows = data.items || [];
    if ($("inboxMeta")) $("inboxMeta").textContent = `${data.count ?? rows.length} items`;
    if ($("inboxSession")) {
      $("inboxSession").textContent = `${data.session || "no session"} · C1+ triage`;
    }
    const body = $("inboxBody");
    if (!body) return;
    body.innerHTML = rows.map((r) => `
      <tr>
        <td>${esc(r.confidence || "")}</td>
        <td>${esc(r.severity || "")}</td>
        <td>${esc(r.module || "")}</td>
        <td>${esc((r.title || "").slice(0, 48))}</td>
        <td>${esc((r.asset || "").slice(0, 56))}</td>
        <td>${esc(r.score ?? "")}</td>
        <td>${esc(r.technique || "—")}</td>
      </tr>
    `).join("") || `<tr><td colspan="7" class="muted">Inbox empty — run recon + reindex</td></tr>`;
  } catch (e) {
    const body = $("inboxBody");
    if (body) body.innerHTML = `<tr><td colspan="7">${esc(e.message)}</td></tr>`;
  }
}

async function loadProofs() {
  const params = new URLSearchParams();
  if (state.target) params.set("target", state.target);
  if (state.proofStatus) params.set("status", state.proofStatus);
  params.set("limit", "100");
  try {
    const data = await api(`/api/proofs?${params}`);
    const rows = data.proofs || data.records || [];
    $("proofMeta").textContent = `${rows.length} proofs`;
    $("proofsBody").innerHTML = rows.map((p) => `
      <tr>
        <td>${esc(p.status)}</td>
        <td>${esc(p.technique || p.tech)}</td>
        <td>${esc(p.target)}</td>
        <td>${esc(p.title || p.summary || "")}</td>
      </tr>
    `).join("") || `<tr><td colspan="4" class="muted">No proofs yet — run /prove</td></tr>`;
  } catch (e) {
    $("proofsBody").innerHTML = `<tr><td colspan="4">${esc(e.message)}</td></tr>`;
  }
}

async function loadGraph() {
  const minScore = ($("graphMinScore") && $("graphMinScore").value) || state.graphMinScore || 40;
  state.graphMinScore = Number(minScore) || 0;
  const p = new URLSearchParams();
  if (state.target) p.set("target", state.target);
  p.set("min_score", String(state.graphMinScore));
  p.set("max_nodes", "80");
  try {
    const data = await api("/api/graph?" + p.toString());
    const nodes = data.nodes || [];
    if ($("graphStats")) {
      $("graphStats").textContent = `${nodes.length} nodes`;
    }
    const empty = $("graphEmpty");
    if (empty) empty.classList.toggle("hidden", nodes.length > 0);
    const body = $("graphBody");
    if (body) {
      body.innerHTML = nodes.slice(0, 80).map((n) => `
        <tr>
          <td>${esc(n.kind || "")}</td>
          <td>${esc(stripAnsi(n.label || n.title || n.id || ""))}</td>
          <td>${esc(n.module || "")}</td>
          <td>${esc(n.score ?? "")}</td>
        </tr>
      `).join("");
    }
  } catch (e) {
    const empty = $("graphEmpty");
    if (empty) {
      empty.classList.remove("hidden");
      empty.textContent = String(e.message || e);
    }
  }
}

async function loadInsights() {
  try {
    const c = await api("/api/stats/charts");
    const root = $("insightsRoot");
    const byMod = c.by_module || c.modules || {};
    root.innerHTML = Object.entries(byMod).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([k, v]) =>
      `<div class="insights-bar"><span>${esc(k)}</span><span>${v}</span></div>`
    ).join("") || "No data — reindex after a scan.";
  } catch (e) {
    $("insightsRoot").textContent = e.message;
  }
}

async function pollStatus() {
  try {
    const st = await api("/api/status");
    const fp = st.disk_fingerprint || st.memory_fingerprint || "";
    const running = String(st.status || "").toLowerCase() === "running" || st.scan_active;
    if (state.fingerprint && fp && fp !== state.fingerprint) {
      state.fingerprint = fp;
      if (state.view === "mission") await loadMission();
      else await refreshAll();
    } else if (!state.fingerprint) {
      state.fingerprint = fp;
    }
    if (state.view === "mission") await loadMission();
    $("footerStatus").textContent = running ? "scan running" : "dashboard";
  } catch (_) { /* ignore */ }
}

function startPoll() {
  if (state.pollTimer) clearInterval(state.pollTimer);
  state.pollTimer = setInterval(pollStatus, 5000);
  pollStatus();
}

async function reindex() {
  $("btnRefresh").textContent = "…";
  try {
    await api("/api/reindex", { method: "POST" });
    await refreshAll();
  } finally {
    $("btnRefresh").textContent = "reindex";
  }
}

async function refreshAll() {
  await loadTargets();
  if (state.view === "mission") await loadMission();
  else if (state.view === "recon") await loadRecon();
  else if (state.view === "inbox") await loadInbox();
  else if (state.view === "proofs") await loadProofs();
  else if (state.view === "graph") await loadGraph();
  else if (state.view === "insights") await loadInsights();
}

function wire() {
  document.querySelectorAll(".btab").forEach((b) => {
    b.onclick = () => setView(b.dataset.view);
  });
  $("btnAllTargets").onclick = () => {
    state.target = "";
    loadTargets();
    refreshAll();
  };
  $("targetSearch").oninput = () => loadTargets();
  $("btnRefresh").onclick = () => reindex();
  $("btnApply").onclick = () => {
    state.module = $("fltModule").value;
    state.severity = $("fltSeverity").value;
    state.type = $("fltType").value;
    state.notable = $("fltNotable").value;
    state.confidence = ($("fltConfidence") && $("fltConfidence").value) || "C1";
    state.q = $("fltQuery").value;
    state.offset = 0;
    loadRecon();
  };
  $("btnClear").onclick = () => {
    state.module = state.severity = state.type = state.notable = state.q = "";
    state.confidence = "C1";
    $("fltModule").value = "";
    $("fltSeverity").value = "";
    $("fltType").value = "";
    $("fltNotable").value = "";
    if ($("fltConfidence")) $("fltConfidence").value = "C1";
    $("fltQuery").value = "";
    state.offset = 0;
    loadRecon();
  };
  const postCtl = async (path) => {
    const res = await fetch(path, { method: "POST", cache: "no-store" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) {
      alert(data.error || res.statusText || "request failed");
      return;
    }
    loadMission();
  };
  if ($("btnQuick")) {
    $("btnQuick").onclick = () => {
      if (!state.target) {
        alert("Select an in-scope target in the list first.");
        return;
      }
      postCtl(`/api/run?target=${encodeURIComponent(state.target)}&modules=quick`);
    };
  }
  if ($("btnPause")) $("btnPause").onclick = () => postCtl("/api/control?action=pause");
  if ($("btnResume")) $("btnResume").onclick = () => postCtl("/api/control?action=resume");
  if ($("btnStop")) $("btnStop").onclick = () => postCtl("/api/control?action=stop");
  $("btnPrev").onclick = () => {
    state.offset = Math.max(0, state.offset - state.limit);
    loadRecon();
  };
  $("btnNext").onclick = () => {
    if (state.offset + state.limit < state.total) {
      state.offset += state.limit;
      loadRecon();
    }
  };
  $("btnProofApply").onclick = () => {
    state.proofStatus = $("fltProofStatus").value;
    loadProofs();
  };
  $("btnGraphReload").onclick = () => {
    state.graphMinScore = Number($("graphMinScore").value) || 40;
    loadGraph();
  };
}

document.addEventListener("DOMContentLoaded", async () => {
  wire();
  await refreshAll();
  startPoll();
  setView("mission");
});
