"""
Mission timeline builder for the Starfleet Bridge console (v3.0.0).

Maps recon modules → starship fleet units and builds a phase-ordered
replay stream (inspired by HF "Anatomy of a Frontier Lab Agent Intrusion"
timeline: play/pause, speed, phase activity, live action stream, chain map).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Recon pipeline order — cyber ops node names (shell.fleet_art)
MISSION_PHASES: list[dict[str, Any]] = [
    {
        "id": "subdomains",
        "ship": "NODE PATHFINDER",
        "class": "Scout",
        "role": "Passive sensors — subdomain constellation map",
        "stage": 1,
        "color": "#ff6b7a",
    },
    {
        "id": "dns",
        "ship": "NODE NAVIGATOR",
        "class": "Science",
        "role": "DNS / CNAME hazard charting",
        "stage": 1,
        "color": "#ff4d5a",
    },
    {
        "id": "httpprobe",
        "ship": "NODE SENSOR",
        "class": "Probe",
        "role": "Active sensor sweep — live host signatures",
        "stage": 1,
        "color": "#e11d2e",
    },
    {
        "id": "tls",
        "ship": "NODE CIPHER",
        "class": "Escort",
        "role": "TLS / JARM fingerprint analysis",
        "stage": 1,
        "color": "#ff8a94",
    },
    {
        "id": "crawl",
        "ship": "NODE SPIDER",
        "class": "Explorer",
        "role": "Surface map — crawl & URL harvest",
        "stage": 2,
        "color": "#fb7185",
    },
    {
        "id": "js",
        "ship": "NODE ARCHIVE",
        "class": "Intel",
        "role": "JS secrets / endpoint extraction",
        "stage": 2,
        "color": "#f43f5e",
    },
    {
        "id": "params",
        "ship": "NODE KEYMASTER",
        "class": "Ops",
        "role": "Parameter mining — latent channels",
        "stage": 2,
        "color": "#ff2a3d",
    },
    {
        "id": "content",
        "ship": "NODE DIG",
        "class": "Survey",
        "role": "Content excavation — paths & fuzz",
        "stage": 2,
        "color": "#e11d48",
    },
    {
        "id": "xss",
        "ship": "NODE MIRROR",
        "class": "Tactical",
        "role": "Reflection hazard scan — XSS canaries",
        "stage": 3,
        "color": "#ef4444",
    },
    {
        "id": "sqli",
        "ship": "NODE ORACLE",
        "class": "Tactical",
        "role": "Query-plane canaries — SQLi detection",
        "stage": 3,
        "color": "#dc2626",
    },
    {
        "id": "ssrf_ssti",
        "ship": "NODE WORMHOLE",
        "class": "Tactical",
        "role": "Trust-boundary probes — SSRF / SSTI",
        "stage": 3,
        "color": "#b91c1c",
    },
    {
        "id": "nuclei",
        "ship": "NODE STRIKE",
        "class": "Battleship",
        "role": "Template volleys — CVE / misconfig",
        "stage": 3,
        "color": "#ff1f33",
    },
    {
        "id": "cloud",
        "ship": "NODE NEBULA",
        "class": "Explorer",
        "role": "Cloud relic survey — S3 / Azure / GCP",
        "stage": 3,
        "color": "#f87171",
    },
    {
        "id": "screenshots",
        "ship": "NODE VIEWSCREEN",
        "class": "Support",
        "role": "Visual recon — capture grid",
        "stage": 3,
        "color": "#9a8e92",
    },
]

PHASE_BY_ID = {p["id"]: p for p in MISSION_PHASES}
PHASE_ORDER = {p["id"]: i for i, p in enumerate(MISSION_PHASES)}

# Trust-boundary chain nodes for the mission map (HF-style attack chain)
CHAIN_NODES: list[dict[str, Any]] = [
    {"id": "scope", "label": "AUTHORIZED SCOPE", "zone": "bridge", "x": 8, "y": 50},
    {"id": "passive", "label": "PASSIVE SENSOR GRID", "zone": "outer", "x": 22, "y": 28},
    {"id": "dns_plane", "label": "DNS HAZARD PLANE", "zone": "outer", "x": 22, "y": 72},
    {"id": "live_hosts", "label": "LIVE HOST CONSTELLATION", "zone": "mid", "x": 40, "y": 50},
    {"id": "tls_shield", "label": "TLS SHIELD ANALYSIS", "zone": "mid", "x": 52, "y": 28},
    {"id": "surface", "label": "SURFACE MAP (CRAWL/JS)", "zone": "mid", "x": 52, "y": 72},
    {"id": "params", "label": "PARAM CHANNELS", "zone": "inner", "x": 68, "y": 40},
    {"id": "vuln", "label": "VULN STRIKE GRID", "zone": "inner", "x": 68, "y": 65},
    {"id": "cloud", "label": "CLOUD RELIC FIELD", "zone": "core", "x": 84, "y": 35},
    {"id": "proof", "label": "PROOF LOCKER", "zone": "core", "x": 84, "y": 65},
    {"id": "report", "label": "MISSION BRIEFING", "zone": "core", "x": 94, "y": 50},
]

CHAIN_EDGES: list[dict[str, str]] = [
    {"from": "scope", "to": "passive"},
    {"from": "scope", "to": "dns_plane"},
    {"from": "passive", "to": "live_hosts"},
    {"from": "dns_plane", "to": "live_hosts"},
    {"from": "live_hosts", "to": "tls_shield"},
    {"from": "live_hosts", "to": "surface"},
    {"from": "surface", "to": "params"},
    {"from": "surface", "to": "vuln"},
    {"from": "tls_shield", "to": "vuln"},
    {"from": "params", "to": "vuln"},
    {"from": "vuln", "to": "cloud"},
    {"from": "vuln", "to": "proof"},
    {"from": "cloud", "to": "report"},
    {"from": "proof", "to": "report"},
]

MODULE_TO_NODES: dict[str, list[str]] = {
    "subdomains": ["passive"],
    "dns": ["dns_plane"],
    "httpprobe": ["live_hosts"],
    "tls": ["tls_shield"],
    "crawl": ["surface"],
    "js": ["surface"],
    "params": ["params"],
    "content": ["params", "surface"],
    "xss": ["vuln"],
    "sqli": ["vuln"],
    "ssrf_ssti": ["vuln"],
    "nuclei": ["vuln"],
    "cloud": ["cloud"],
    "screenshots": ["live_hosts"],
}


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ""


def _module_of(rec: dict[str, Any]) -> str:
    m = str(rec.get("module") or "other").strip().lower()
    if m in PHASE_BY_ID:
        return m
    # normalize aliases
    aliases = {
        "http": "httpprobe",
        "httpx": "httpprobe",
        "subdomain": "subdomains",
        "ssrf": "ssrf_ssti",
        "ssti": "ssrf_ssti",
    }
    return aliases.get(m, m if m in PHASE_BY_ID else "other")


def build_mission(
    idx: dict[str, Any],
    *,
    target: str = "",
    max_actions: int = 800,
) -> dict[str, Any]:
    """
    Build a mission replay payload from the findings index.

    Actions are ordered by pipeline phase, then severity, then title —
    suitable for client-side play/pause timeline (HF intrusion replay style).
    """
    records = list(idx.get("findings") or idx.get("records") or [])
    if target:
        t = target.lower().strip()
        records = [r for r in records if str(r.get("target") or "").lower() == t]

    targets = idx.get("targets") or {}
    # base time from target mtime or index generation
    base_ts = time_base(idx, target)

    # Phase stats
    phase_counts: dict[str, int] = {p["id"]: 0 for p in MISSION_PHASES}
    phase_counts["other"] = 0
    for r in records:
        mid = _module_of(r)
        if mid in phase_counts:
            phase_counts[mid] += 1
        else:
            phase_counts["other"] = phase_counts.get("other", 0) + 1

    # Build action stream (clustered by phase for replay)
    # Sort: phase order, then severity rank, then score desc
    sev_rank = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5,
    }

    def sort_key(r: dict[str, Any]) -> tuple:
        mid = _module_of(r)
        return (
            PHASE_ORDER.get(mid, 99),
            sev_rank.get(str(r.get("severity") or "unknown").lower(), 5),
            -int(r.get("score") or 0),
            str(r.get("title") or ""),
        )

    ordered = sorted(records, key=sort_key)
    # Cap for UI performance but keep phase representatives
    if len(ordered) > max_actions:
        # take top by score within each phase proportionally
        ordered = ordered[:max_actions]

    actions: list[dict[str, Any]] = []
    t_cursor = base_ts
    for i, r in enumerate(ordered):
        mid = _module_of(r)
        meta = PHASE_BY_ID.get(mid, {
            "id": mid, "ship": "USS UNKNOWN", "class": "Utility",
            "role": mid, "stage": 0, "color": "#64748b",
        })
        # Spread timestamps by ~30s for replay pacing
        t_cursor = base_ts + i * 30
        title = str(r.get("title") or r.get("asset") or "signal")
        asset = str(r.get("asset") or "")
        actions.append({
            "i": i,
            "ts": t_cursor,
            "ts_iso": _iso(t_cursor),
            "phase": mid,
            "ship": meta.get("ship"),
            "ship_class": meta.get("class"),
            "color": meta.get("color"),
            "stage": meta.get("stage"),
            "severity": r.get("severity") or "info",
            "ftype": r.get("ftype") or "other",
            "title": title[:160],
            "asset": asset[:120],
            "score": int(r.get("score") or 0),
            "notable": bool(r.get("notable")),
            "evidence": str(r.get("evidence") or "")[:280],
            "source_file": r.get("source_file") or "",
            "id": r.get("id") or "",
            "nodes": MODULE_TO_NODES.get(mid, []),
        })

    # Phase activity bars (first/last action index)
    phase_activity: list[dict[str, Any]] = []
    for p in MISSION_PHASES:
        pid = p["id"]
        idxs = [a["i"] for a in actions if a["phase"] == pid]
        phase_activity.append({
            **p,
            "count": phase_counts.get(pid, 0),
            "replay_count": len(idxs),
            "first_i": min(idxs) if idxs else None,
            "last_i": max(idxs) if idxs else None,
            "active": bool(idxs) or phase_counts.get(pid, 0) > 0,
            "status": (
                "complete" if phase_counts.get(pid, 0) > 0 else "standby"
            ),
        })

    # Volume by "day" buckets (synthetic 5 slots from action density)
    n_act = max(1, len(actions))
    bucket_n = 5
    volumes = [0] * bucket_n
    for a in actions:
        b = min(bucket_n - 1, int(a["i"] * bucket_n / n_act))
        volumes[b] += 1

    # Fleet board: every ship status + ASCII hull art for the bridge UI
    try:
        from shell.fleet_art import (
            MODULE_SHIP_ART,
            RECONKIT_WORDMARK,
        )
        FLAGSHIP = ""
        SPACEDOCK = ""
    except Exception:
        MODULE_SHIP_ART = {}
        FLAGSHIP = ""
        RECONKIT_WORDMARK = "RECONKIT"
        SPACEDOCK = ""

    fleet = []
    for p in MISSION_PHASES:
        c = phase_counts.get(p["id"], 0)
        art = MODULE_SHIP_ART.get(p["id"], MODULE_SHIP_ART.get("default", ""))
        art_lines = [ln for ln in str(art).splitlines() if ln.strip()][:14]
        fleet.append({
            **p,
            "signals": c,
            "status": "engaged" if c > 0 else "docked",
            "orders": p["role"],
            "art": art_lines,
        })

    # Blast radius / mission posture
    crit = sum(1 for r in records if str(r.get("severity")).lower() == "critical")
    high = sum(1 for r in records if str(r.get("severity")).lower() == "high")
    notable = sum(1 for r in records if r.get("notable"))
    if crit:
        blast = "red-alert"
        blast_detail = f"{crit} critical signal(s) — priority triage"
    elif high:
        blast = "yellow-alert"
        blast_detail = f"{high} high signal(s) — elevated watch"
    elif notable:
        blast = "condition-blue"
        blast_detail = f"{notable} notable finding(s)"
    else:
        blast = "green"
        blast_detail = "nominal — detection sweep only"

    # Proofs
    proof_n = 0
    try:
        from prove.store import proofs_overview
        pov = proofs_overview(target=target) if target else proofs_overview()
        proof_n = int(pov.get("confirmed") or 0)
    except Exception:
        pass

    active_phases = sum(1 for p in phase_activity if p["count"] > 0)
    stages_seen = sorted({p["stage"] for p in phase_activity if p["count"] > 0 and p.get("stage")})

    tgt_label = target or "FLEET-WIDE"
    return {
        "version": "3.0.0",
        "mission_id": f"MISSION-{tgt_label.upper().replace('.', '-')}",
        "codename": "STARFLEET RECON OPS",
        "target": target or "",
        "target_label": tgt_label,
        "generated_at": idx.get("generated_at"),
        "base_ts": base_ts,
        "base_ts_iso": _iso(base_ts),
        "summary": {
            "actions_total": len(records),
            "actions_replay": len(actions),
            "phases_total": len(MISSION_PHASES),
            "phases_active": active_phases,
            "stages": stages_seen or [1],
            "stages_label": f"{len(stages_seen) or 1} stage(s)",
            "fleet_ships": len(MISSION_PHASES),
            "ships_engaged": sum(1 for s in fleet if s["status"] == "engaged"),
            "critical": crit,
            "high": high,
            "notable": notable,
            "proofs_confirmed": proof_n,
            "blast": blast,
            "blast_detail": blast_detail,
        },
        "phases": phase_activity,
        "fleet": fleet,
        "logos": {
            "wordmark": RECONKIT_WORDMARK,
            "flagship": FLAGSHIP,
            "spacedock": SPACEDOCK,
            "source": "pure-ascii RECONKIT + asciiart.eu ships/dock",
            "ships_source": "asciiart.eu/television/star-trek",
        },
        "actions": actions,
        "volumes": [
            {"slot": i + 1, "label": f"SEG-{i + 1}", "count": volumes[i]}
            for i in range(bucket_n)
        ],
        "chain": {
            "nodes": CHAIN_NODES,
            "edges": CHAIN_EDGES,
            "module_nodes": MODULE_TO_NODES,
        },
        "playback": {
            "speeds": [0.5, 1, 2, 4, 8],
            "default_speed": 1,
            "tick_ms": 400,
        },
    }


def build_live_tracker(
    idx: dict[str, Any],
    *,
    target: str = "",
) -> dict[str, Any]:
    """
    Live phase tracker for the bridge UI (no replay).

    Merges disk-backed live_mission.json (current run) with findings counts
    so tiles show: pending / running / complete / idle.
    """
    from live_mission import read_live

    live = read_live()
    records = list(idx.get("findings") or idx.get("records") or [])
    tgt_filter = (target or live.get("target") or "").strip()
    if tgt_filter:
        tlow = tgt_filter.lower()
        records = [r for r in records if str(r.get("target") or "").lower() == tlow]

    phase_counts: dict[str, int] = {p["id"]: 0 for p in MISSION_PHASES}
    for r in records:
        mid = _module_of(r)
        if mid in phase_counts:
            phase_counts[mid] += 1

    run_modules = list(live.get("modules") or [])
    # Tiles = modules in the active/last run, else full pipeline catalog
    if run_modules:
        tile_ids = [m for m in run_modules if m in PHASE_BY_ID]
    else:
        tile_ids = [p["id"] for p in MISSION_PHASES]

    completed = set(live.get("completed") or [])
    current = str(live.get("current_module") or "")
    active = bool(live.get("active")) and not live.get("stale")
    status = str(live.get("status") or "idle")

    # If run finished, treat all modules in list as complete when in completed set
    tiles: list[dict[str, Any]] = []
    lit_nodes: set[str] = set()
    active_nodes: set[str] = set()
    if active or completed or status in ("complete", "running", "paused", "stopping"):
        lit_nodes.add("scope")

    for i, mid in enumerate(tile_ids, 1):
        meta = PHASE_BY_ID.get(mid) or {
            "id": mid,
            "ship": mid,
            "class": "",
            "role": "",
            "stage": 0,
            "color": "#5eead4",
        }
        signals = int(phase_counts.get(mid, 0))
        if active and mid == current:
            st = "running"
        elif mid in completed:
            st = "complete"
        elif active and run_modules:
            # pending if later in the queue
            try:
                cur_i = run_modules.index(current) if current in run_modules else -1
                my_i = run_modules.index(mid)
                st = "pending" if my_i > cur_i else ("complete" if my_i < cur_i else "pending")
            except ValueError:
                st = "pending"
        elif signals > 0:
            st = "complete"
        else:
            st = "idle"

        # chain lights
        nodes = MODULE_TO_NODES.get(mid, [])
        if st == "complete":
            lit_nodes.update(nodes)
        if st == "running":
            lit_nodes.update(nodes)
            active_nodes.update(nodes)

        tiles.append({
            **meta,
            "index": i,
            "total": len(tile_ids),
            "status": st,
            "signals": signals,
            "orders": meta.get("role") or "",
        })

    if status == "complete" or (not active and completed):
        lit_nodes.add("report")
    # proofs node if any confirmed
    proof_n = 0
    try:
        from prove.store import proofs_overview
        pov = proofs_overview(target=tgt_filter) if tgt_filter else proofs_overview()
        proof_n = int(pov.get("confirmed") or 0)
        if proof_n:
            lit_nodes.add("proof")
    except Exception:
        pass

    done_n = sum(1 for t in tiles if t["status"] == "complete")
    run_n = sum(1 for t in tiles if t["status"] == "running")
    total_n = len(tiles)
    pct = int(round(100.0 * done_n / total_n)) if total_n else 0

    host_cur = int(live.get("host_current") or 0)
    host_tot = int(live.get("host_total") or 0)
    host_pct = int(round(100.0 * host_cur / host_tot)) if host_tot else 0

    current_meta = PHASE_BY_ID.get(current) or {}
    tool = str(live.get("current_tool") or "")
    return {
        "version": "3.0.0",
        "mode": "live_tracker",
        "mission_id": f"LIVE-{(tgt_filter or 'FLEET').upper().replace('.', '-')}",
        "codename": "LIVE PHASE TRACKER",
        "target": tgt_filter,
        "target_label": tgt_filter or "FLEET-WIDE",
        "live": live,
        "active": active,
        "status": status,
        "current_module": current,
        "current_tool": tool,
        "current_ship": current_meta.get("ship") or current or "—",
        "current_class": current_meta.get("class") or "",
        "current_color": current_meta.get("color") or "#5eead4",
        "message": live.get("message") or "",
        "live_path": live.get("_path") or "",
        "age_s": live.get("age_s"),
        "source": live.get("source") or "",
        "summary": {
            "phases_total": total_n,
            "phases_complete": done_n,
            "phases_running": run_n,
            "phases_pending": sum(1 for t in tiles if t["status"] == "pending"),
            "pct": pct,
            "host_current": host_cur,
            "host_total": host_tot,
            "host_pct": host_pct,
            "signals_total": len(records),
            "proofs_confirmed": proof_n,
            "elapsed_s": live.get("elapsed_s") or 0,
            "control": live.get("control") or status,
            "current_tool": tool,
            "age_s": live.get("age_s"),
            "live_path": live.get("_path") or "",
            "source": live.get("source") or "",
        },
        "tiles": tiles,
        "chain": {
            "nodes": CHAIN_NODES,
            "edges": CHAIN_EDGES,
            "module_nodes": MODULE_TO_NODES,
            "lit": sorted(lit_nodes),
            "active": sorted(active_nodes),
        },
        "fleet": [
            {
                **PHASE_BY_ID[t["id"]],
                "signals": t["signals"],
                "status": (
                    "engaged" if t["status"] in ("running", "complete") else "docked"
                ),
                "orders": t.get("orders") or "",
            }
            for t in tiles
            if t["id"] in PHASE_BY_ID
        ],
    }


def time_base(idx: dict[str, Any], target: str = "") -> float:
    import time as _time
    targets = idx.get("targets") or {}
    if target and isinstance(targets.get(target), dict):
        mt = float(targets[target].get("mtime") or 0)
        if mt > 0:
            return mt
    # any target mtime
    best = 0.0
    for _t, meta in targets.items():
        if isinstance(meta, dict):
            best = max(best, float(meta.get("mtime") or 0))
    if best > 0:
        return best
    # parse generated_at
    gen = str(idx.get("generated_at") or "")
    if gen:
        try:
            # ISO-ish
            return datetime.fromisoformat(gen.replace("Z", "+00:00")).timestamp()
        except Exception:
            pass
    return _time.time()
