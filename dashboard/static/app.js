/* RECONKIT dashboard */

const state = {
  view: "mission",
  target: "",
  module: "",
  severity: "",
  type: "",
  notable: "",
  confidence: "C1",
  q: "",
  limit: 100,
  offset: 0,
  total: 0,
  proofStatus: "",
  proofOffset: 0,
  proofLimit: 100,
  graphMinScore: 40,
  live: true,
  pollTimer: null,
  fingerprint: "",
  mission: null,
  fleetArt: null, // /api/fleet/art cache
  selected: null,
  missionPoll: null, // live tracker interval
  // Tactical map (SVG force layout — pan/zoom/drag/click)
  graphData: null,
  graphSim: null,
  graphCtrl: null,
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

function truncate(s, n = 80) {
  s = stripAnsi(s);
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/** Safe plain text for textContent / titles. */
function cleanText(s) {
  return stripAnsi(s).trim();
}

/* ---------------- Views ---------------- */
function setView(name) {
  state.view = name;
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll(".btab").forEach((b) => b.classList.remove("active"));
  // ids: viewMission, viewRecon, viewInbox, viewProofs, viewGraph, viewInsights
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
  if (name !== "graph") destroyGraphCtrl();
  if (name !== "mission") stopMissionPoll();
  if (name === "mission") loadMission();
  if (name === "recon") loadRecon();
  if (name === "inbox") loadInbox();
  if (name === "proofs") loadProofs();
  if (name === "graph") loadGraph();
  if (name === "insights") loadInsights();
}

/* ---------------- Targets ---------------- */
async function loadTargets() {
  const data = await api("/api/targets");
  const list = data.targets || data || [];
  state.targets = list;
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
    li.innerHTML = `<span>${esc(name)}</span><span class="meta">${count} signals</span>`;
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

/* ---------------- Live phase tracker ---------------- */
async function loadFleetArt() {
  if (state.fleetArt) return state.fleetArt;
  try {
    state.fleetArt = await api("/api/fleet/art");
  } catch (_) {
    state.fleetArt = { logos: {}, ships: {} };
  }
  return state.fleetArt;
}

function startMissionPoll() {
  stopMissionPoll();
  // 1s poll while mission tab is open so phase tiles track active scans
  state.missionPoll = setInterval(() => {
    if (state.view === "mission") loadMission({ quiet: true });
  }, 1000);
}

function stopMissionPoll() {
  if (state.missionPoll) {
    clearInterval(state.missionPoll);
    state.missionPoll = null;
  }
}

async function loadMission(opts = {}) {
  await loadFleetArt();
  const q = new URLSearchParams();
  if (state.target) q.set("target", state.target);
  q.set("mode", "live");
  const m = await api(`/api/mission?${q}`);
  state.mission = m;
  if (!opts.quiet) renderLogos(m);
  renderLiveTracker(m);
  renderPhaseTiles(m);
  renderLiveChain(m);
  renderFleet(m, m.current_module || null);
  updateLiveKpis(m);
  startMissionPoll();
}

function renderLiveTracker(m) {
  const s = m.summary || {};
  const st = (m.status || "idle").toUpperCase();
  const active = !!m.active;

  $("missionBanner").textContent = active
    ? `LIVE · ${m.current_module || "…"} · ${s.phases_complete ?? 0}/${s.phases_total ?? 0}`
    : `${m.mission_id || "TRACKER"} · ${s.phases_complete ?? 0}/${s.phases_total ?? 0} phases known`;
  $("missionTitle").textContent = m.codename || "Live phase tracker";
  $("missionKicker").textContent = active
    ? `Live · ${m.target_label || "target"} · ${m.message || "scanning"}`
    : `Tracker · ${m.target_label || "all targets"} · start a scan to watch phases`;

  $("missionPills").innerHTML = [
    `<span class="mpill">${esc(m.target_label || "all")}</span>`,
    `<span class="mpill">${s.phases_complete ?? 0} / ${s.phases_total ?? 0} phases</span>`,
    `<span class="mpill">${s.signals_total ?? 0} signals</span>`,
    `<span class="mpill">${s.pct ?? 0}%</span>`,
  ].join("");

  const label = $("liveStatusLabel");
  const strip = $("liveStrip");
  if (label) label.textContent = st;
  if (strip) {
    strip.classList.remove("st-idle", "st-running", "st-paused", "st-complete", "st-failed");
    const cls = active ? (st === "PAUSED" ? "st-paused" : "st-running")
      : (st === "COMPLETE" ? "st-complete" : st === "FAILED" ? "st-failed" : "st-idle");
    strip.classList.add(cls);
  }
  const tool = m.current_tool || s.current_tool || "";
  if ($("liveMessage")) {
    $("liveMessage").textContent = m.message || m.current_ship || "—";
  }
  if ($("livePhaseFrac")) {
    $("livePhaseFrac").textContent =
      `${s.phases_complete ?? 0} / ${s.phases_total ?? 0} phases`
      + (tool ? ` · tool ${tool}` : "")
      + (m.current_module ? ` · ${m.current_module}` : "");
  }
  if ($("liveHostFrac")) {
    const hc = s.host_current ?? 0;
    const ht = s.host_total ?? 0;
    $("liveHostFrac").textContent = ht ? `hosts ${hc}/${ht}` : "hosts —";
  }
  if ($("liveElapsed")) {
    const age = m.age_s != null ? m.age_s : s.age_s;
    $("liveElapsed").textContent =
      `${s.elapsed_s ?? 0}s` + (age != null ? ` · beat ${age}s ago` : "");
  }
  if ($("liveProgressBar")) {
    $("liveProgressBar").style.width = `${Math.min(100, s.pct ?? 0)}%`;
  }
  if ($("phaseTilesChip")) {
    const src = m.source || s.source || "";
    $("phaseTilesChip").textContent = active
      ? `live · ${s.phases_total ?? 0} phase(s)${src ? " · " + src : ""}`
      : `${s.phases_total ?? 0} phase tile(s) · idle`;
  }

  const pill = $("alertPill");
  if (active) {
    pill.className = "alert-pill yellow";
    pill.textContent = st === "PAUSED" ? "SCAN PAUSED" : "SCAN LIVE";
  } else if (st === "COMPLETE") {
    pill.className = "alert-pill green";
    pill.textContent = "SCAN COMPLETE";
  } else {
    pill.className = "alert-pill green";
    pill.textContent = "IDLE";
  }
}

function renderPhaseTiles(m) {
  const root = $("phaseTiles");
  if (!root) return;
  const tiles = m.tiles || [];
  if (!tiles.length) {
    root.innerHTML = `<p class="muted" style="padding:16px">No phases yet — run a scan with /run</p>`;
    return;
  }
  root.innerHTML = tiles.map((t, i) => {
    const st = t.status || "idle";
    const hostBar = st === "running" && (m.summary?.host_total || 0) > 0
      ? `<div class="tile-hostbar"><i style="width:${m.summary.host_pct || 0}%"></i></div>
         <div class="tile-hostlbl">${m.summary.host_current}/${m.summary.host_total} hosts</div>`
      : "";
    const toolHint = st === "running" && (m.current_tool || m.summary?.current_tool)
      ? `<div class="tile-tool">tool · ${esc(m.current_tool || m.summary.current_tool)}</div>`
      : "";
    return `<div class="phase-tile st-${esc(st)}" data-phase="${esc(t.id)}" style="--tile:${esc(t.color || "#5eead4")}">
      <div class="tile-top">
        <span class="tile-badge">${esc(st)}</span>
      </div>
      <div class="tile-ship">${esc(t.ship || t.id)}</div>
      <div class="tile-mod">${esc(t.id)} · ${esc(t.class || "")}</div>
      <div class="tile-role">${esc((t.role || t.orders || "").slice(0, 72))}</div>
      ${toolHint}
      ${hostBar}
      <div class="tile-foot">
        <span class="tile-sig">${t.signals || 0} signals</span>
      </div>
    </div>`;
  }).join("");
  root.querySelectorAll(".phase-tile").forEach((el) => {
    el.onclick = () => {
      const id = el.dataset.phase;
      const tile = (m.tiles || []).find((x) => x.id === id);
      if (tile) showDetailPhase(tile, m);
    };
  });
}

function showDetailPhase(t, m) {
  const body = $("detailBody");
  if (!body) return;
  body.innerHTML = `
    <h3>${esc(t.ship || t.id)}</h3>
    <div class="kv">
      <span class="k">module</span><span>${esc(t.id)}</span>
      <span class="k">class</span><span>${esc(t.class || "")}</span>
      <span class="k">status</span><span>${esc(t.status || "")}</span>
      <span class="k">stage</span><span>${esc(t.stage || "")}</span>
      <span class="k">signals</span><span>${t.signals || 0}</span>
      <span class="k">run</span><span>${esc(m.status || "")} · ${esc(m.target_label || "")}</span>
    </div>
    <p class="muted">${esc(t.role || t.orders || "")}</p>
  `;
}

function renderLiveChain(m) {
  const lit = new Set(m.chain?.lit || ["scope"]);
  const active = new Set(m.chain?.active || []);
  renderChain(m, lit, active);
}

function updateLiveKpis(m) {
  const s = m.summary || {};
  $("kpiActions").textContent = String(s.phases_complete ?? 0);
  $("kpiActionsSub").textContent =
    `of ${s.phases_total ?? 0} in this scan · ${s.pct ?? 0}%`;
  if (m.active && m.current_module) {
    $("kpiPhase").textContent = m.current_module;
    const tool = m.current_tool || s.current_tool || "";
    $("kpiPhaseSub").textContent =
      `${m.current_ship || ""} · ${tool || "running"} · hosts ${s.host_current ?? 0}/${s.host_total ?? 0}`;
  } else {
    $("kpiPhase").textContent = "—";
    $("kpiPhaseSub").textContent = m.status === "complete"
      ? "last run complete"
      : "no scan in progress — start /run or /agent";
  }
  $("kpiBlast").textContent = (s.control || m.status || "idle").toUpperCase();
  $("kpiBlastSub").textContent = m.message || "start a scan with /run";
  const card = $("kpiBlastCard");
  card.classList.remove("alert-red", "alert-yellow");
  if (m.active) card.classList.add("alert-yellow");
}

function RS() {
  return window.ReconShips || null;
}

function shipSvgFor(s, size) {
  const api = RS();
  if (!api) return "";
  return api.svgShip({
    module: s.id || s.module,
    class: s.class,
    color: s.color || "#5eead4",
    width: size?.w || 148,
    height: size?.h || 56,
    glow: s.status === "engaged" || s.status === "active",
    animate: true,
  });
}

function renderLogos(_m) {
  // Compact brand
  if ($("logoWordmark")) {
    $("logoWordmark").innerHTML = `
      <div class="reconkit-fallback">RECONKIT</div>
      <div class="cyber-tag">[//] CYBER OPS NODE</div>
    `;
  }
  if ($("logoFlagship")) {
    $("logoFlagship").innerHTML = "";
    $("logoFlagship").style.display = "none";
  }
  if ($("logoDockArt")) {
    $("logoDockArt").innerHTML = "";
    $("logoDockArt").style.display = "none";
  }
}

function renderFleet(m, activePhase) {
  const root = $("fleetBoard");
  if (!root) return;
  root.innerHTML = (m.fleet || []).map((s) => {
    const eng = (s.status === "engaged" || s.status === "active") ? "engaged" : "";
    const act = activePhase === s.id ? "active" : "";
    return `<div class="ship-card ${eng} ${act}" data-phase="${esc(s.id)}">
      <div class="ship-card-main">
        <div class="ship-head">
          <div>
            <div class="nm" style="color:${esc(s.color || "#e8eef7")}">${esc(s.ship)}</div>
            <div class="mod">${esc(s.id)} · ${esc(s.class)} · ${esc(s.status)}</div>
          </div>
        </div>
      </div>
      <div class="sig">${s.signals || 0}</div>
    </div>`;
  }).join("");
  root.querySelectorAll(".ship-card").forEach((el) => {
    el.onclick = () => {
      const id = el.dataset.phase;
      const tile = (m.tiles || m.fleet || []).find((x) => x.id === id);
      if (tile) showDetailPhase(tile, m);
    };
  });
}

function resetGraphNodePanel() {
  const root = $("tacticalFleetList");
  if (!root) return;
  if ($("nodeDetailChip")) $("nodeDetailChip").textContent = "click a host";
  root.innerHTML =
    `<p class="muted" style="padding:8px">Click a hostname on the map to inspect target, module, score, and linked evidence.</p>`;
}

function renderChain(m, litNodes, activeNodes = new Set()) {
  const svg = $("chainSvg");
  const nodes = m.chain?.nodes || [];
  const edges = m.chain?.edges || [];
  const W = 1000, H = 360;

  const pos = {};
  nodes.forEach((n) => {
    pos[n.id] = { x: (n.x / 100) * W, y: (n.y / 100) * H };
  });

  let edgesSvg = edges.map((e) => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return "";
    const lit = litNodes.has(e.from) && litNodes.has(e.to) ? "lit" : "";
    return `<path class="chain-edge ${lit}" d="M${a.x},${a.y} L${b.x},${b.y}" />`;
  }).join("");

  let nodesSvg = nodes.map((n) => {
    const p = pos[n.id];
    const lit = litNodes.has(n.id) ? "lit" : "";
    const act = activeNodes.has(n.id) ? "active" : "";
    const label = (n.label || n.id).split(" ").slice(0, 3).join(" ");
    return `<g class="chain-node ${lit} ${act}" data-id="${esc(n.id)}" transform="translate(${p.x},${p.y})">
      <circle r="18" />
      <text text-anchor="middle" y="36">${esc(label)}</text>
    </g>`;
  }).join("");

  svg.innerHTML = edgesSvg + nodesSvg;
}

/* ---------------- Sensors / recon table ---------------- */
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

  // module filter options
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
      $("inboxSession").textContent =
        `${data.session || "no session"} · C1+ notable, ranked for triage. Suggested prove technique on the right.`;
    }
    const body = $("inboxBody");
    if (!body) return;
    body.innerHTML = rows.map((r) => `
      <tr>
        <td>${esc(r.confidence || "")}</td>
        <td>${esc(r.severity || "")}</td>
        <td>${esc(r.module || "")}</td>
        <td>${esc((r.title || "").slice(0, 48))}</td>
        <td title="${esc(r.asset || "")}">${esc((r.asset || "").slice(0, 56))}</td>
        <td>${esc(r.score ?? "")}</td>
        <td>${esc(r.technique || "—")}</td>
      </tr>
    `).join("") || `<tr><td colspan="7" class="muted">Inbox empty — run recon + $ reindex. Set /session for authenticated diffs.</td></tr>`;
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

/* ---------- Attack graph (SVG force layout + pan/zoom/drag, from v2.2) ---------- */
const KIND_COLOR = {
  target: "#f5a623",
  host: "#5eead4",
  url: "#38bdf8",
  secret: "#fb7185",
  vuln: "#ff2a3d",
  proof: "#34d399",
  finding: "#99ccff",
  module: "#cc99cc",
  module_bucket: "#cc99cc",
  default: "#99ccff",
};

async function loadGraph() {
  const minScore =
    ($("graphMinScore") && $("graphMinScore").value) || state.graphMinScore || 40;
  state.graphMinScore = Number(minScore) || 0;
  const p = new URLSearchParams();
  if (state.target) p.set("target", state.target);
  p.set("min_score", String(state.graphMinScore));
  p.set("max_nodes", "160");
  try {
    const data = await api("/api/graph?" + p.toString());
    state.graphData = data;
    const st = data.stats || {};
    if ($("graphStats")) {
      $("graphStats").textContent =
        `${st.node_count || (data.nodes || []).length || 0} nodes · ${st.edge_count || (data.edges || []).length || 0} edges` +
        (state.target ? ` · ${state.target}` : "");
    }
    resetGraphNodePanel();
    renderGraph(data);
  } catch (e) {
    state.graphData = null;
    destroyGraphCtrl();
    const svg = $("graphSvg");
    if (svg) svg.innerHTML = "";
    const empty = $("graphEmpty");
    if (empty) {
      empty.classList.remove("hidden");
      empty.textContent = String(e.message || e);
    }
    if ($("graphStats")) $("graphStats").textContent = "error";
  }
}

function destroyGraphCtrl() {
  if (state.graphSim) {
    cancelAnimationFrame(state.graphSim);
    state.graphSim = null;
  }
  if (state.graphCtrl && typeof state.graphCtrl.destroy === "function") {
    state.graphCtrl.destroy();
  }
  state.graphCtrl = null;
}

/**
 * Convert browser client coords → SVG viewBox coords (0..width, 0..height).
 */
function clientToSvg(svg, clientX, clientY, width, height) {
  const rect = svg.getBoundingClientRect();
  if (!rect.width || !rect.height) return { x: 0, y: 0 };
  return {
    x: ((clientX - rect.left) / rect.width) * width,
    y: ((clientY - rect.top) / rect.height) * height,
  };
}

function renderGraph(data) {
  const svg = $("graphSvg");
  const empty = $("graphEmpty");
  if (!svg) return;

  destroyGraphCtrl();

  const nodes = (data.nodes || []).map((n) => ({ ...n }));
  const links = (data.edges || []).map((e) => ({
    ...e,
    source: e.source ?? e.from,
    target: e.target ?? e.to,
  }));
  if (!nodes.length) {
    svg.innerHTML = "";
    if (empty) {
      empty.classList.remove("hidden");
      empty.textContent = "No graph data — run recon + reindex first.";
    }
    if ($("graphStats")) $("graphStats").textContent = "0 nodes";
    return;
  }
  if (empty) empty.classList.add("hidden");

  const wrap = $("graphViewport");
  const width = Math.max((wrap && wrap.clientWidth) || 800, 400);
  const height = Math.max((wrap && wrap.clientHeight) || 520, 420);
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", "100%");
  svg.setAttribute("height", "100%");
  svg.innerHTML = "";

  // Viewport transform: pan (tx, ty) + zoom (k)
  const xf = { x: 0, y: 0, k: 1 };
  const byId = {};
  nodes.forEach((n) => {
    byId[n.id] = n;
    n.x = width / 2 + (Math.random() - 0.5) * width * 0.45;
    n.y = height / 2 + (Math.random() - 0.5) * height * 0.45;
    n.vx = 0;
    n.vy = 0;
    n.fx = null;
    n.fy = null;
  });
  const resolvedLinks = links
    .map((l) => ({
      ...l,
      source: byId[typeof l.source === "object" ? l.source.id : l.source],
      target: byId[typeof l.target === "object" ? l.target.id : l.target],
    }))
    .filter((l) => l.source && l.target);

  const gWorld = document.createElementNS("http://www.w3.org/2000/svg", "g");
  gWorld.setAttribute("class", "graph-world");
  const gLinks = document.createElementNS("http://www.w3.org/2000/svg", "g");
  gLinks.setAttribute("class", "graph-links");
  const gNodes = document.createElementNS("http://www.w3.org/2000/svg", "g");
  gNodes.setAttribute("class", "graph-nodes");
  gWorld.appendChild(gLinks);
  gWorld.appendChild(gNodes);
  svg.appendChild(gWorld);

  function applyViewTransform() {
    gWorld.setAttribute(
      "transform",
      `translate(${xf.x},${xf.y}) scale(${xf.k})`
    );
    if ($("zoomLabel")) {
      $("zoomLabel").textContent = Math.round(xf.k * 100) + "%";
    }
  }
  applyViewTransform();

  function clientToWorld(clientX, clientY) {
    const s = clientToSvg(svg, clientX, clientY, width, height);
    return {
      x: (s.x - xf.x) / xf.k,
      y: (s.y - xf.y) / xf.k,
    };
  }

  const linkEls = resolvedLinks.map((l) => {
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("class", "graph-link rel-" + (l.rel || "link"));
    gLinks.appendChild(line);
    return { line, l };
  });

  let selectedNodeId = null;

  const nodeEls = nodes.map((n) => {
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    g.setAttribute("class", "graph-node");
    g.setAttribute("data-id", n.id);
    g.style.cursor = "pointer";
    const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    const r =
      n.kind === "target"
        ? 14
        : n.kind === "proof"
          ? 10
          : 8 + Math.min(6, (n.score || 0) / 40);
    c.setAttribute("r", String(r));
    c.setAttribute("fill", KIND_COLOR[n.kind] || KIND_COLOR.finding);
    c.setAttribute("opacity", "0.92");
    // Always print hostname / label under the node
    const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
    t.setAttribute("dy", String(r + 14));
    t.setAttribute("text-anchor", "middle");
    t.setAttribute("class", "graph-node-label");
    const label = cleanText(n.label || n.title || n.id || n.kind) || "node";
    t.textContent = truncate(label, 36);
    t.setAttribute("title", label);
    // Invisible hit target so labels + circle are easy to click
    const hit = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    hit.setAttribute("r", String(Math.max(r + 10, 18)));
    hit.setAttribute("fill", "transparent");
    hit.setAttribute("class", "graph-node-hit");
    g.appendChild(hit);
    g.appendChild(c);
    g.appendChild(t);
    gNodes.appendChild(g);

    // Node pointer: drag node + click → detail (hostname info)
    g.addEventListener("pointerdown", (ev) => {
      if (ev.button !== 0) return;
      ev.preventDefault();
      ev.stopPropagation();
      const startWorld = clientToWorld(ev.clientX, ev.clientY);
      const originX = n.x;
      const originY = n.y;
      let moved = false;
      n.fx = n.x;
      n.fy = n.y;
      g.classList.add("dragging");
      try {
        g.setPointerCapture(ev.pointerId);
      } catch (_) {
        /* ignore */
      }

      const onMove = (e) => {
        const w = clientToWorld(e.clientX, e.clientY);
        const dx = w.x - startWorld.x;
        const dy = w.y - startWorld.y;
        if (Math.abs(dx) + Math.abs(dy) > 3 / xf.k) moved = true;
        n.fx = originX + dx;
        n.fy = originY + dy;
        n.x = n.fx;
        n.y = n.fy;
        n.vx = 0;
        n.vy = 0;
        paint();
      };
      const onUp = () => {
        g.classList.remove("dragging");
        n.fx = null;
        n.fy = null;
        try {
          g.releasePointerCapture(ev.pointerId);
        } catch (_) {
          /* ignore */
        }
        g.removeEventListener("pointermove", onMove);
        g.removeEventListener("pointerup", onUp);
        g.removeEventListener("pointercancel", onUp);
        if (!moved) {
          selectedNodeId = n.id;
          nodeEls.forEach(({ g: gg, n: nn }) => {
            gg.classList.toggle("selected", nn.id === selectedNodeId);
          });
          showGraphNodeDetail(n);
        }
      };
      g.addEventListener("pointermove", onMove);
      g.addEventListener("pointerup", onUp);
      g.addEventListener("pointercancel", onUp);
    });

    return { g, c, t, n, r };
  });

  function paint() {
    linkEls.forEach(({ line, l }) => {
      line.setAttribute("x1", l.source.x);
      line.setAttribute("y1", l.source.y);
      line.setAttribute("x2", l.target.x);
      line.setAttribute("y2", l.target.y);
    });
    nodeEls.forEach(({ g, n }) => {
      g.setAttribute("transform", `translate(${n.x},${n.y})`);
    });
  }

  function tick() {
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const rep = 900 / dist;
        dx = (dx / dist) * rep * 0.02;
        dy = (dy / dist) * rep * 0.02;
        a.vx -= dx;
        a.vy -= dy;
        b.vx += dx;
        b.vy += dy;
      }
    }
    resolvedLinks.forEach((l) => {
      const a = l.source;
      const b = l.target;
      let dx = b.x - a.x;
      let dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const ideal = 95;
      const f = (dist - ideal) * 0.012;
      dx = (dx / dist) * f;
      dy = (dy / dist) * f;
      a.vx += dx;
      a.vy += dy;
      b.vx -= dx;
      b.vy -= dy;
    });
    nodes.forEach((n) => {
      n.vx += (width / 2 - n.x) * 0.004;
      n.vy += (height / 2 - n.y) * 0.004;
      if (n.fx != null) {
        n.x = n.fx;
        n.y = n.fy;
        n.vx = 0;
        n.vy = 0;
      } else {
        n.vx *= 0.86;
        n.vy *= 0.86;
        n.x += n.vx;
        n.y += n.vy;
        n.x = Math.max(-width, Math.min(width * 2, n.x));
        n.y = Math.max(-height, Math.min(height * 2, n.y));
      }
    });
    paint();
  }

  function zoomAt(clientX, clientY, factor) {
    const s = clientToSvg(svg, clientX, clientY, width, height);
    const next = Math.min(6, Math.max(0.2, xf.k * factor));
    xf.x = s.x - (s.x - xf.x) * (next / xf.k);
    xf.y = s.y - (s.y - xf.y) * (next / xf.k);
    xf.k = next;
    applyViewTransform();
  }

  function zoomCenter(factor) {
    const s = { x: width / 2, y: height / 2 };
    const next = Math.min(6, Math.max(0.2, xf.k * factor));
    xf.x = s.x - (s.x - xf.x) * (next / xf.k);
    xf.y = s.y - (s.y - xf.y) * (next / xf.k);
    xf.k = next;
    applyViewTransform();
  }

  function resetView() {
    xf.x = 0;
    xf.y = 0;
    xf.k = 1;
    applyViewTransform();
  }

  const onWheel = (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
    const factor = ev.deltaY > 0 ? 0.9 : 1.12;
    zoomAt(ev.clientX, ev.clientY, factor);
  };
  const wheelTarget = wrap || svg;
  wheelTarget.addEventListener("wheel", onWheel, { passive: false });

  // Pan (drag empty canvas)
  let pan = null;
  const onSvgPointerDown = (ev) => {
    if (ev.button !== 0) return;
    const t = ev.target;
    if (t && t.closest && t.closest(".graph-node")) return;
    ev.preventDefault();
    const start = clientToSvg(svg, ev.clientX, ev.clientY, width, height);
    pan = {
      pointerId: ev.pointerId,
      sx: start.x,
      sy: start.y,
      ox: xf.x,
      oy: xf.y,
    };
    svg.classList.add("panning");
    if (wrap) wrap.classList.add("dragging");
    try {
      svg.setPointerCapture(ev.pointerId);
    } catch (_) {
      /* ignore */
    }
  };
  const onSvgPointerMove = (ev) => {
    if (!pan || pan.pointerId !== ev.pointerId) return;
    const cur = clientToSvg(svg, ev.clientX, ev.clientY, width, height);
    xf.x = pan.ox + (cur.x - pan.sx);
    xf.y = pan.oy + (cur.y - pan.sy);
    applyViewTransform();
  };
  const onSvgPointerUp = (ev) => {
    if (!pan || pan.pointerId !== ev.pointerId) return;
    pan = null;
    svg.classList.remove("panning");
    if (wrap) wrap.classList.remove("dragging");
    try {
      svg.releasePointerCapture(ev.pointerId);
    } catch (_) {
      /* ignore */
    }
  };
  svg.addEventListener("pointerdown", onSvgPointerDown);
  svg.addEventListener("pointermove", onSvgPointerMove);
  svg.addEventListener("pointerup", onSvgPointerUp);
  svg.addEventListener("pointercancel", onSvgPointerUp);

  const onZoomIn = (e) => {
    e.preventDefault();
    zoomCenter(1.25);
  };
  const onZoomOut = (e) => {
    e.preventDefault();
    zoomCenter(0.8);
  };
  const onZoomReset = (e) => {
    e.preventDefault();
    resetView();
  };
  if ($("btnZoomIn")) $("btnZoomIn").addEventListener("click", onZoomIn);
  if ($("btnZoomOut")) $("btnZoomOut").addEventListener("click", onZoomOut);
  if ($("btnZoomReset")) $("btnZoomReset").addEventListener("click", onZoomReset);

  state.graphCtrl = {
    destroy() {
      wheelTarget.removeEventListener("wheel", onWheel);
      svg.removeEventListener("pointerdown", onSvgPointerDown);
      svg.removeEventListener("pointermove", onSvgPointerMove);
      svg.removeEventListener("pointerup", onSvgPointerUp);
      svg.removeEventListener("pointercancel", onSvgPointerUp);
      if ($("btnZoomIn")) $("btnZoomIn").removeEventListener("click", onZoomIn);
      if ($("btnZoomOut")) $("btnZoomOut").removeEventListener("click", onZoomOut);
      if ($("btnZoomReset")) $("btnZoomReset").removeEventListener("click", onZoomReset);
      svg.classList.remove("panning");
      if (wrap) wrap.classList.remove("dragging");
    },
  };

  // Force simulation (layout only; interactions keep working after it stops)
  let frames = 0;
  function loop() {
    tick();
    frames++;
    if (frames < 240) {
      state.graphSim = requestAnimationFrame(loop);
    } else {
      state.graphSim = null;
      paint();
    }
  }
  loop();
}

/** Show hostname / node info in VIEWSCREEN + tactical side panel. */
function showGraphNodeDetail(n) {
  if (!n) return;
  state.selected = n;
  const label = cleanText(n.label || n.title || n.id || n.kind) || "node";
  const kind = cleanText(n.kind) || "node";
  const target = cleanText(n.target) || "—";
  const mod = cleanText(n.module || n.kind) || "—";
  const sev = cleanText(n.severity) || "—";
  const score = n.score != null ? n.score : "—";
  const title = cleanText(n.title) || "";
  const meta = {
    id: n.id,
    kind: n.kind,
    label: cleanText(n.label),
    title,
    target: n.target,
    module: n.module,
    severity: n.severity,
    score: n.score,
    finding_id: n.finding_id,
    proof_id: n.proof_id,
  };
  const source = n.finding_id
    ? "finding:" + cleanText(n.finding_id)
    : n.proof_id
      ? "proof:" + cleanText(n.proof_id)
      : "—";

  if ($("nodeDetailChip")) $("nodeDetailChip").textContent = kind;

  // Side panel on the map
  const side = $("tacticalFleetList");
  if (side) {
    side.innerHTML = `
      <div class="node-detail-card">
        <div class="nd-host">${esc(label)}</div>
        <div class="kv">
          <div class="k">Kind</div><div>${esc(kind)}</div>
          <div class="k">Target</div><div>${esc(target)}</div>
          <div class="k">Module</div><div>${esc(mod)}</div>
          <div class="k">Severity</div><div><span class="${sevClass(sev)}">${esc(sev)}</span></div>
          <div class="k">Score</div><div>${esc(score)}</div>
          <div class="k">Source</div><div>${esc(source)}</div>
          <div class="k">Node ID</div><div class="nd-id">${esc(n.id || "—")}</div>
        </div>
        ${title ? `<div class="nd-title">${esc(title)}</div>` : ""}
        <pre>${esc(JSON.stringify(meta, null, 2).slice(0, 1400))}</pre>
      </div>`;
  }

  // Global VIEWSCREEN rail
  const body = $("detailBody");
  if (body) {
    body.innerHTML = `
      <h3>${esc(label)}</h3>
      <div class="kv">
        <div class="k">Kind</div><div>${esc(kind)}</div>
        <div class="k">Target</div><div>${esc(target)}</div>
        <div class="k">Module</div><div>${esc(mod)}</div>
        <div class="k">Severity</div><div><span class="${sevClass(sev)}">${esc(sev)}</span></div>
        <div class="k">Score</div><div>${esc(score)}</div>
        <div class="k">Asset</div><div>${esc(label)}</div>
        <div class="k">Source</div><div>${esc(source)}</div>
        <div class="k">Node ID</div><div>${esc(n.id || "—")}</div>
      </div>
      ${title ? `<p class="nd-title">${esc(title)}</p>` : ""}
      <pre>${esc((title ? title + "\n\n" : "") + JSON.stringify(meta, null, 2).slice(0, 1200))}</pre>
    `;
  }
}

function wireGraphControls() {
  // Zoom / pan / click are bound inside renderGraph per load.
  // Reload button is wired in wire().
}

async function loadInsights() {
  try {
    const c = await api("/api/stats/charts");
    const root = $("insightsRoot");
    const byMod = c.by_module || c.modules || {};
    const max = Math.max(1, ...Object.values(byMod).map(Number));
    root.innerHTML = `<h3 style="font-family:Orbitron,sans-serif;font-size:12px;color:#ffcc80">BY MODULE</h3>` +
      Object.entries(byMod).sort((a, b) => b[1] - a[1]).map(([k, v]) => `
        <div class="insights-bar">
          <span style="width:120px">${esc(k)}</span>
          <div class="fill" style="width:${Math.round((v / max) * 60)}%"></div>
          <span>${v}</span>
        </div>
      `).join("");
  } catch (e) {
    $("insightsRoot").textContent = e.message;
  }
}

/* ---------------- Live / reindex ---------------- */
async function pollStatus() {
  if (!state.live) return;
  try {
    const st = await api("/api/status");
    const fp = st.disk_fingerprint || st.memory_fingerprint || "";
    if (state.fingerprint && fp && fp !== state.fingerprint) {
      state.fingerprint = fp;
      refreshAll();
    } else if (!state.fingerprint) {
      state.fingerprint = fp;
    }
    $("liveBadge").classList.toggle("on", true);
    $("liveBadge").innerHTML = `<span class="dot"></span>LIVE ON`;
    $("footerStatus").textContent = st.stale ? "BRIDGE · TELEMETRY STALE" : "BRIDGE ONLINE";
  } catch (_) { /* ignore */ }
}

function setLive(on) {
  state.live = on;
  if (state.pollTimer) clearInterval(state.pollTimer);
  if (on) {
    state.pollTimer = setInterval(pollStatus, 4000);
    pollStatus();
  } else {
    $("liveBadge").classList.remove("on");
    $("liveBadge").innerHTML = `<span class="dot"></span>LIVE OFF`;
  }
}

async function reindex() {
  $("btnRefresh").textContent = "…";
  try {
    await api("/api/reindex", { method: "POST" });
    await refreshAll();
  } finally {
    $("btnRefresh").textContent = "$ reindex";
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

/* ---------------- Wire UI ---------------- */
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
  $("btnLive").onclick = () => setLive(!state.live);
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
    loadMission({ quiet: true });
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

  wireGraphControls();

  // stars sprinkle
  const stars = $("stars");
  if (stars) {
    let bg = "";
    for (let i = 0; i < 40; i++) {
      const x = Math.random() * 100, y = Math.random() * 100, s = Math.random() * 1.5 + 0.5;
      bg += `radial-gradient(${s}px ${s}px at ${x}% ${y}%, rgba(255,255,255,0.85) 50%, transparent 51%),`;
    }
    stars.style.background = bg.slice(0, -1);
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  wire();
  setLive(true);
  await loadFleetArt();
  renderLogos({});
  await refreshAll();
  setView("mission");
});
