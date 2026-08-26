"""
Local recon dashboard server (stdlib only).

  python recon_dashboard.py
  python recon_dashboard.py --host 0.0.0.0 --port 8787   # default: reachable from host/LAN
  python recon_dashboard.py --host 127.0.0.1               # localhost only

Live data:
  - Memory cache is invalidated when ~/.reconkit/output changes (fingerprint)
  - POST /api/reindex forces a full rebuild
  - GET /api/status exposes fingerprint for client auto-refresh
  - UI polls status and reloads when scans write new files (no server restart)

API (JSON):
  GET  /api/health
  GET  /api/status
  GET  /api/overview
  GET  /api/targets
  GET  /api/targets/<target>
  GET  /api/records  (preferred)  +  /api/findings (compat)
  GET  /api/proofs
  GET  /api/proofs/overview
  GET  /api/graph
  GET  /api/stats/charts
  GET  /api/program
  GET  /api/scan                 # live phase tracker (alias: /api/mission)
  GET  /api/scan?mode=replay     # findings replay stream
  POST /api/run                  # start scoped scan (target, modules)
  POST /api/control              # pause | resume | stop
  GET  /api/run                  # scan control status
  POST /api/reindex
  GET  /api/file?target=&path=   # JSON preview; too_large files include raw_url
  GET  /raw/<target>/<path>      # GitHub-style text/plain (50 MB cap)
  GET  /api/inbox                # hunter C1+ triage queue
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from findings.indexer import (  # noqa: E402
    filter_findings,
    filter_stats,
    get_or_build_index,
    index_all_targets,
    list_targets,
    output_fingerprint,
    query_store,
)
from findings.store import OUTPUT_DIR  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"

_LOCK = threading.Lock()
_INDEX: dict[str, Any] | None = None
_INDEX_FP: str = ""  # fingerprint the cache was built for


def _force_rebuild() -> dict[str, Any]:
    """Always re-parse disk output; update memory cache."""
    global _INDEX, _INDEX_FP
    idx = index_all_targets(persist=True)
    fp = str(idx.get("output_fingerprint") or output_fingerprint().get("token") or "")
    with _LOCK:
        _INDEX = idx
        _INDEX_FP = fp
    return idx


def _get_index(*, force: bool = False) -> dict[str, Any]:
    """Return index, rebuilding when forced or when scan output changed."""
    global _INDEX, _INDEX_FP
    live_fp = str(output_fingerprint().get("token") or "")

    with _LOCK:
        cached = _INDEX
        cached_fp = _INDEX_FP

    if force or cached is None or (live_fp and live_fp != cached_fp):
        # Rebuild outside the lock (indexing can be slow); then publish.
        idx = get_or_build_index(refresh=True)
        # get_or_build_index may no-op rebuild if fingerprint already on disk index
        # matches — but if memory was stale relative to live_fp, force full reindex:
        if force or str(idx.get("output_fingerprint") or "") != live_fp:
            idx = index_all_targets(persist=True)
        fp = str(idx.get("output_fingerprint") or live_fp)
        # Do not keep the full findings array in RAM — SQLite is the query path.
        try:
            from findings.db import slim_payload, usable
            if usable(fp):
                idx = slim_payload()
        except Exception:
            idx = dict(idx)
            idx["findings"] = []
            idx["records"] = []
        with _LOCK:
            _INDEX = idx
            _INDEX_FP = fp
        return idx

    return cached  # type: ignore[return-value]


def _json_bytes(obj: Any, status: int = 200) -> tuple[int, bytes, str]:
    body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    return status, body, "application/json; charset=utf-8"


def _overview(idx: dict[str, Any]) -> dict[str, Any]:
    records = idx.get("findings") or idx.get("records") or []
    by_sev: dict[str, int] = {}
    by_mod: dict[str, int] = {}
    by_type: dict[str, int] = {}
    if records:
        for f in records:
            by_sev[f.get("severity", "unknown")] = by_sev.get(f.get("severity", "unknown"), 0) + 1
            by_mod[f.get("module", "other")] = by_mod.get(f.get("module", "other"), 0) + 1
            by_type[f.get("ftype", "other")] = by_type.get(f.get("ftype", "other"), 0) + 1
    else:
        try:
            from findings.db import query_stats, usable
            if usable(str(idx.get("output_fingerprint") or "")):
                st = query_stats()
                by_sev = st.get("by_severity") or {}
                by_mod = st.get("by_module") or {}
                by_type = st.get("by_type") or {}
        except Exception:
            pass
    n = idx.get("finding_count", len(records))
    fp = output_fingerprint()
    out: dict[str, Any] = {
        "version": idx.get("version", "3.0.0"),
        "generated_at": idx.get("generated_at"),
        "output_dir": idx.get("output_dir", str(OUTPUT_DIR)),
        "target_count": idx.get("target_count", len(idx.get("targets") or {})),
        "record_count": n,
        "finding_count": n,  # backward-compatible alias
        "by_severity": by_sev,
        "by_module": by_mod,
        "by_type": by_type,
        "targets": list((idx.get("targets") or {}).keys()),
        "output_fingerprint": idx.get("output_fingerprint") or fp.get("token"),
        "disk_fingerprint": fp.get("token"),
        "stale": (idx.get("output_fingerprint") or "") != (fp.get("token") or ""),
        "proof_count": 0,
        "proof_confirmed": 0,
        "proof_needs_manual": 0,
        "proof_by_status": {},
    }
    try:
        from prove.store import proofs_overview

        pov = proofs_overview()
        out["proof_count"] = pov.get("proof_count", 0)
        out["proof_confirmed"] = pov.get("confirmed", 0)
        out["proof_needs_manual"] = pov.get("needs_manual", 0)
        out["proof_by_status"] = pov.get("by_status") or {}
    except Exception:
        pass
    return out


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "reconkit-dashboard/3.0.0"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[dash] " + (fmt % args) + "\n")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj: Any, status: int = 200) -> None:
        st, body, ct = _json_bytes(obj, status)
        self._send(st, body, ct)

    def _send_raw(self, path: str) -> None:
        """GitHub-style raw file: GET /raw/<target>/<relative-path> as text/plain."""
        rest = unquote(path[len("/raw/"):]).lstrip("/")
        if "/" not in rest:
            self._send_json({"error": "usage: /raw/<target>/<path>"}, 400)
            return
        target, rel = rest.split("/", 1)
        from dashboard.outputs import resolve_output_path
        full, err = resolve_output_path(target, rel)
        if err or full is None:
            self._send_json({"error": err or "file not found"}, 404)
            return
        if full.stat().st_size > 50_000_000:
            self._send_json({
                "error": "file larger than 50 MB — open it on disk",
                "disk_path": str(full),
                "size": full.stat().st_size,
            }, 413)
            return
        data = full.read_bytes()
        # Prefer UTF-8 text in the browser; fallback latin-1 so bytes always display.
        try:
            data.decode("utf-8")
            ctype = "text/plain; charset=utf-8"
        except UnicodeDecodeError:
            ctype = "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'inline; filename="{full.name}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Reconkit-Disk-Path", str(full))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        qs = parse_qs(parsed.query)

        if path.startswith("/api/"):
            self._api_get(path, qs)
            return

        if path.startswith("/raw/"):
            self._send_raw(path)
            return

        if path in ("", "/"):
            path = "/index.html"
        self._static(path)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        post_body = self.rfile.read(n) if n > 0 else b""

        if path in ("/api/reindex", "/api/refresh"):
            t0 = time.time()
            idx = _force_rebuild()
            elapsed = time.time() - t0
            n = idx.get("finding_count", 0)
            self._send_json({
                "ok": True,
                "generated_at": idx.get("generated_at"),
                "target_count": idx.get("target_count"),
                "record_count": n,
                "finding_count": n,
                "output_fingerprint": idx.get("output_fingerprint"),
                "elapsed_s": round(elapsed, 2),
            })
            return

        if path in ("/api/run", "/api/scan/start"):
            qs = parse_qs(urlparse(self.path).query)
            target = (qs.get("target") or [""])[0]
            modules = (qs.get("modules") or ["quick"])[0]
            if post_body:
                try:
                    obj = json.loads(post_body.decode("utf-8"))
                    target = str(obj.get("target") or target)
                    modules = str(obj.get("modules") or modules)
                except Exception:
                    pass
            try:
                from dashboard.control import start_scan
                self._send_json(start_scan(target=target, modules=modules, source="dashboard"))
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
            return

        if path in ("/api/prompt", "/api/ask"):
            try:
                obj = json.loads(post_body.decode("utf-8") or "{}")
            except Exception:
                self._send_json({"ok": False, "error": "invalid JSON"}, 400)
                return
            from dashboard.prompt import run_prompt
            self._send_json(run_prompt(
                prompt=str(obj.get("prompt") or ""),
                target=str(obj.get("target") or ""),
                path=str(obj.get("path") or ""),
            ))
            return

        if path in ("/api/control", "/api/scan/control"):
            qs = parse_qs(urlparse(self.path).query)
            action = (qs.get("action") or [""])[0].lower()
            try:
                from dashboard.control import pause, resume, stop
                if action == "pause":
                    self._send_json({"ok": True, **pause()})
                elif action == "resume":
                    self._send_json({"ok": True, **resume()})
                elif action in ("stop", "kill"):
                    self._send_json({"ok": True, **stop()})
                else:
                    self._send_json({"error": "action must be pause|resume|stop"}, 400)
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
            return
        self._send_json({"error": "not found"}, 404)

    def _api_get(self, path: str, qs: dict[str, list[str]]) -> None:
        def q(name: str, default: str = "") -> str:
            vals = qs.get(name) or []
            return vals[0] if vals else default

        force = q("refresh", "").lower() in ("1", "true", "yes") or q("reindex", "").lower() in (
            "1", "true", "yes",
        )

        if path in ("/api/run", "/api/scan/status"):
            from dashboard.control import status as run_status
            self._send_json(run_status())
            return

        if path == "/api/health":
            self._send_json({
                "ok": True,
                "service": "reconkit-dashboard",
                "version": "3.0.0",
                "codename": "recon-dashboard",
            })
            return

        if path in ("/api/scan", "/api/mission", "/api/mission/live", "/api/tracker", "/api/run/live"):
            # Live tracker reads live_mission.json only — do not rebuild the findings index.
            target = q("target")
            mode = (q("mode") or "live").strip().lower()
            if mode in ("replay", "playback", "legacy"):
                idx = _get_index(force=force)
                try:
                    max_a = int(q("max_actions") or "800")
                except ValueError:
                    max_a = 800
                from dashboard.mission import build_mission
                self._send_json(build_mission(idx, target=target, max_actions=max_a))
            else:
                from dashboard.mission import build_live_tracker
                self._send_json(build_live_tracker({}, target=target))
            return

        if path in ("/api/scan/modules", "/api/mission/fleet", "/api/fleet"):
            idx = _get_index(force=force)
            target = q("target")
            from dashboard.mission import build_live_tracker
            m = build_live_tracker(idx, target=target)
            self._send_json({
                "fleet": m.get("fleet"),
                "summary": m.get("summary"),
                "mission_id": m.get("mission_id"),
                "target": m.get("target"),
                "tiles": m.get("tiles"),
                "status": m.get("status"),
                "active": m.get("active"),
            })
            return

        if path in ("/api/modules/meta", "/api/fleet/art", "/api/art", "/api/logos"):
            try:
                from shell.fleet_art import (
                    MODULE_SHIP_ART,
                    MODULE_SHIP_META,
                    RECONKIT_WORDMARK,
                )
                ships = {}
                for mod, meta in MODULE_SHIP_META.items():
                    name, klass = meta if isinstance(meta, tuple) else (mod, "")
                    art = MODULE_SHIP_ART.get(mod, "")
                    ships[mod] = {
                        "id": mod,
                        "label": name,
                        "ship": name,
                        "class": klass,
                        "art": str(art).splitlines() if art else [],
                    }
                self._send_json({
                    "logos": {
                        "wordmark": RECONKIT_WORDMARK,
                        "flagship": "",
                        "spacedock": "",
                    },
                    "modules": ships,
                    "ships": ships,
                    "source": {
                        "banner": "RECONKIT",
                        "ships": "module names",
                    },
                })
            except Exception as e:
                self._send_json({"error": str(e), "ships": {}, "logos": {}}, status=500)
            return

        if path == "/api/status":
            fp = output_fingerprint()
            with _LOCK:
                mem_fp = _INDEX_FP
                gen = (_INDEX or {}).get("generated_at", "")
                n = (_INDEX or {}).get("finding_count", 0)
                notable = (_INDEX or {}).get("notable_count", 0)
            stale = bool(fp.get("token") and fp.get("token") != mem_fp)
            try:
                from prove.store import proofs_overview

                pov = proofs_overview()
                proof_count = pov.get("proof_count", 0)
                proof_confirmed = pov.get("confirmed", 0)
            except Exception:
                proof_count, proof_confirmed = 0, 0
            self._send_json({
                "ok": True,
                "disk_fingerprint": fp.get("token"),
                "memory_fingerprint": mem_fp,
                "stale": stale,
                "generated_at": gen,
                "record_count": n,
                "notable_count": notable,
                "proof_count": proof_count,
                "proof_confirmed": proof_confirmed,
                "target_count": fp.get("target_count"),
                "file_count": fp.get("file_count"),
                "output_dir": str(OUTPUT_DIR),
                "server_time": time.time(),
            })
            return

        if path == "/api/diff":
            from findings.history import diff_target
            target = q("target")
            if not target:
                self._send_json({"error": "target required"}, 400)
                return
            self._send_json(diff_target(target))
            return

        if path == "/api/overview":
            idx = _get_index(force=force)
            base = _overview(idx)
            base["notable_count"] = idx.get("notable_count", 0)
            base["notable_threshold"] = idx.get("notable_threshold", 40)
            # Optional filters → KPIs reflect the active filter set (not only global)
            ft = q("target") or None
            fm = q("module") or None
            fs = q("severity") or None
            fty = q("type") or None
            fq = q("q") or None
            notable = q("notable", "").lower() in ("1", "true", "yes")
            min_conf = q("min_confidence") or q("min_conf") or ""
            conf = q("confidence") or ""
            min_score = None
            if q("min_score"):
                try:
                    min_score = int(q("min_score"))
                except ValueError:
                    min_score = None
            if any((ft, fm, fs, fty, fq, notable, min_score is not None, min_conf, conf)):
                _rows, stats = query_store(
                    target=ft,
                    module=fm,
                    severity=fs,
                    ftype=fty,
                    q=fq,
                    notable=True if notable else None,
                    min_score=min_score,
                    confidence=conf or None,
                    min_confidence=min_conf or None,
                    limit=1,
                    offset=0,
                )
                base["filtered"] = True
                base["record_count"] = stats["total"]
                base["finding_count"] = stats["total"]
                base["notable_count"] = stats.get("notable_count", 0)
                base["by_severity"] = stats["by_severity"]
                base["by_module"] = stats["by_module"]
                base["by_type"] = stats["by_type"]
                base["filters"] = {
                    "target": ft or "",
                    "module": fm or "",
                    "severity": fs or "",
                    "type": fty or "",
                    "q": fq or "",
                    "notable": notable,
                    "min_score": min_score if min_score is not None else "",
                }
            else:
                base["filtered"] = False
            self._send_json(base)
            return

        if path == "/api/targets":
            idx = _get_index(force=force)
            targets = dict(idx.get("targets") or {})
            for t in list_targets():
                targets.setdefault(t, {
                    "target": t,
                    "outdir": str(OUTPUT_DIR / t),
                    "finding_count": 0,
                    "record_count": 0,
                })
            # normalize counts for UI
            rows = []
            for info in targets.values():
                row = dict(info)
                c = row.get("finding_count") or row.get("record_count") or 0
                row["finding_count"] = c
                row["record_count"] = c
                rows.append(row)
            rows.sort(key=lambda x: x.get("target", ""))
            self._send_json({
                "targets": rows,
                "output_fingerprint": idx.get("output_fingerprint"),
            })
            return

        if path.startswith("/api/targets/"):
            target = path[len("/api/targets/"):].strip("/")
            if not target:
                self._send_json({"error": "target required"}, 400)
                return
            idx = _get_index(force=force)
            info = (idx.get("targets") or {}).get(target)
            if not info:
                # maybe new target on disk not yet in index
                idx = _get_index(force=True)
                info = (idx.get("targets") or {}).get(target)
            if not info:
                self._send_json({"error": "unknown target", "target": target}, 404)
                return
            self._send_json({"target": info})
            return

        if path in ("/api/findings", "/api/records"):
            idx = _get_index(force=force)
            try:
                limit = int(q("limit", "200"))
                offset = int(q("offset", "0"))
            except ValueError:
                limit, offset = 200, 0
            limit = max(1, min(limit, 2000))
            offset = max(0, offset)
            ft = q("target") or None
            fm = q("module") or None
            fs = q("severity") or None
            fty = q("type") or None
            fq = q("q") or None
            notable = q("notable", "").lower() in ("1", "true", "yes")
            # Default: hide C0 inventory. Pass min_confidence=C0 or confidence=all to see everything.
            raw_min = (q("min_confidence") or q("min_conf") or "").upper()
            raw_conf = (q("confidence") or "").upper()
            if raw_conf in ("ALL", "C0") or raw_min == "C0":
                min_conf = ""
                conf = ""
            elif raw_conf in ("C1", "C2", "C3", "C4"):
                min_conf = raw_conf
                conf = ""
            elif raw_min in ("C1", "C2", "C3", "C4"):
                min_conf = raw_min
                conf = ""
            else:
                min_conf = "C1"
                conf = ""
            min_score = None
            if q("min_score"):
                try:
                    min_score = int(q("min_score"))
                except ValueError:
                    min_score = None
            rows, stats = query_store(
                target=ft,
                module=fm,
                severity=fs,
                ftype=fty,
                q=fq,
                notable=True if notable else None,
                min_score=min_score,
                confidence=conf or None,
                min_confidence=min_conf or None,
                limit=limit,
                offset=offset,
            )
            total = stats["total"]
            # Default hides C0 inventory. If that empties the page, show C0
            # rather than a blank dashboard (common for dns/httpprobe-only runs).
            confidence_fallback = ""
            if total == 0 and min_conf == "C1" and not conf and not notable:
                min_conf = ""
                rows, stats = query_store(
                    target=ft, module=fm, severity=fs, ftype=fty, q=fq,
                    notable=None, min_score=min_score,
                    confidence=None, min_confidence=None,
                    limit=limit, offset=offset,
                )
                total = stats["total"]
                if total:
                    confidence_fallback = "C0"
            # Clamp offset so filters never return an empty page due to old pagination
            if offset >= total and total > 0:
                offset = 0
                rows, stats = query_store(
                    target=ft, module=fm, severity=fs, ftype=fty, q=fq,
                    notable=True if notable else None, min_score=min_score,
                    confidence=conf or None, min_confidence=min_conf or None,
                    limit=limit, offset=0,
                )
            self._send_json({
                "total": total,
                "offset": offset,
                "limit": limit,
                "records": rows,
                "findings": rows,  # compat
                "by_severity": stats["by_severity"],
                "by_module": stats["by_module"],
                "by_type": stats["by_type"],
                "notable_count": stats.get("notable_count", 0),
                "filters": {
                    "target": ft or "",
                    "module": fm or "",
                    "severity": fs or "",
                    "type": fty or "",
                    "q": fq or "",
                    "notable": notable,
                    "min_score": min_score if min_score is not None else "",
                    "min_confidence": min_conf,
                    "confidence": conf,
                    "confidence_fallback": confidence_fallback,
                },
                "output_fingerprint": idx.get("output_fingerprint"),
                "generated_at": idx.get("generated_at"),
            })
            return

        if path in ("/api/outputs", "/api/files"):
            target = q("target")
            if not target:
                self._send_json({"error": "target required"}, 400)
                return
            from dashboard.outputs import list_output_files
            self._send_json(list_output_files(target))
            return

        if path in ("/api/llm", "/api/prompt"):
            from dashboard.prompt import llm_status
            self._send_json(llm_status())
            return

        if path == "/api/file":
            target = q("target")
            rel = q("path")
            if not target or not rel:
                self._send_json({"error": "target and path required"}, 400)
                return
            from dashboard.outputs import read_output_file
            rec = read_output_file(target, rel)
            status = 200 if not rec.get("error") or rec.get("too_large") else 404
            if rec.get("error") == "invalid path" or rec.get("error") == "path outside target dir":
                status = 400
            self._send_json(rec, status)
            return

        if path == "/api/modules":
            mods: list[str] = []
            try:
                from findings.db import list_modules
                mods = list_modules()
            except Exception:
                idx = _get_index(force=force)
                mods = sorted({
                    f.get("module", "other")
                    for f in (idx.get("findings") or [])
                    if f.get("module")
                })
            if not mods:
                try:
                    from reconkit import ALL_MODULES
                    mods = list(ALL_MODULES)
                except Exception:
                    mods = []
            self._send_json({"modules": mods})
            return

        if path in ("/api/inbox", "/api/hunter"):
            from hunter.ops import build_inbox
            try:
                limit = int(q("limit", "40"))
            except ValueError:
                limit = 40
            payload = build_inbox(target=q("target") or None, limit=limit)
            self._send_json(payload)
            return

        # --- Prove layer (safe validation results) ---
        if path in ("/api/proofs/overview", "/api/prove/overview"):
            from prove.store import proofs_overview

            ft = q("target") or None
            ov = proofs_overview(ft)
            # merge recon fingerprint so LIVE clients can refresh
            fp = output_fingerprint()
            ov["disk_fingerprint"] = fp.get("token")
            ov["output_dir"] = str(OUTPUT_DIR)
            self._send_json(ov)
            return

        if path in ("/api/proofs", "/api/prove"):
            from prove.store import filter_proofs, load_all_proofs

            try:
                limit = int(q("limit", "100"))
                offset = int(q("offset", "0"))
            except ValueError:
                limit, offset = 100, 0
            limit = max(1, min(limit, 2000))
            offset = max(0, offset)
            ft = q("target") or None
            st = q("status") or None
            tech = q("technique") or None
            fq = q("q") or None
            all_p = load_all_proofs(ft)
            page, stats = filter_proofs(
                all_p,
                target=ft,
                status=st,
                technique=tech,
                q=fq,
                limit=limit,
                offset=offset,
            )
            fp = output_fingerprint()
            self._send_json({
                "total": stats["total"],
                "offset": stats["offset"],
                "limit": stats["limit"],
                "proofs": page,
                "records": page,
                "by_status": stats["by_status"],
                "by_technique": stats["by_technique"],
                "by_target": stats["by_target"],
                "confirmed": stats["confirmed"],
                "needs_manual": stats["needs_manual"],
                "filters": {
                    "target": ft or "",
                    "status": st or "",
                    "technique": tech or "",
                    "q": fq or "",
                },
                "disk_fingerprint": fp.get("token"),
            })
            return

        if path in ("/api/graph", "/api/attack-graph"):
            from graph.builder import build_graph

            ft = q("target") or None
            try:
                max_nodes = int(q("max_nodes", "180"))
                min_score = int(q("min_score", "0"))
            except ValueError:
                max_nodes, min_score = 180, 0
            g = build_graph(
                target=ft,
                max_nodes=max(20, min(max_nodes, 400)),
                min_score=max(0, min_score),
                include_proofs=q("proofs", "1").lower() not in ("0", "false", "no"),
            )
            self._send_json(g)
            return

        if path in ("/api/stats/charts", "/api/charts"):
            idx = _get_index(force=force)
            ft = q("target") or None
            records, stats = query_store(target=ft, limit=5000, offset=0)
            if not records:
                records = idx.get("findings") or []
                if ft:
                    records = [r for r in records if r.get("target") == ft]
            by_sev: dict[str, int] = dict(stats.get("by_severity") or {})
            by_mod: dict[str, int] = dict(stats.get("by_module") or {})
            by_type: dict[str, int] = dict(stats.get("by_type") or {})
            score_buckets = {"0-39": 0, "40-74": 0, "75-99": 0, "100+": 0}
            fill_dims = not by_sev
            for r in records:
                if fill_dims:
                    by_sev[r.get("severity", "unknown")] = by_sev.get(r.get("severity", "unknown"), 0) + 1
                    by_mod[r.get("module", "other")] = by_mod.get(r.get("module", "other"), 0) + 1
                    by_type[r.get("ftype", "other")] = by_type.get(r.get("ftype", "other"), 0) + 1
                sc = int(r.get("score") or 0)
                if sc >= 100:
                    score_buckets["100+"] += 1
                elif sc >= 75:
                    score_buckets["75-99"] += 1
                elif sc >= 40:
                    score_buckets["40-74"] += 1
                else:
                    score_buckets["0-39"] += 1
            proof_by_status: dict[str, int] = {}
            try:
                from prove.store import proofs_overview

                pov = proofs_overview(ft)
                proof_by_status = pov.get("by_status") or {}
            except Exception:
                pass
            prog = {}
            try:
                from programs.profiles import get_active_profile

                p = get_active_profile()
                prog = {"name": p.get("name"), "display_name": p.get("display_name")}
            except Exception:
                pass
            self._send_json({
                "target": ft or "",
                "by_severity": by_sev,
                "by_module": by_mod,
                "by_type": by_type,
                "score_buckets": score_buckets,
                "proof_by_status": proof_by_status,
                "program": prog,
                "record_count": len(records),
            })
            return

        if path in ("/api/program", "/api/programs"):
            try:
                from programs.profiles import get_active_profile, list_profiles

                active = get_active_profile()
                self._send_json({
                    "active": {
                        "name": active.get("name"),
                        "display_name": active.get("display_name"),
                        "notable_threshold": active.get("notable_threshold"),
                        "max_risk_class": active.get("max_risk_class"),
                    },
                    "profiles": list_profiles(),
                })
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        if path.startswith("/api/proofs/") and path.count("/") >= 3:
            # /api/proofs/<target>/<id>
            from prove.store import load_proofs

            rest = path[len("/api/proofs/"):].strip("/")
            parts = rest.split("/")
            if len(parts) >= 2:
                target, pid = parts[0], parts[1]
                for p in load_proofs(target):
                    if p.get("id") == pid or str(p.get("id", "")).startswith(pid):
                        self._send_json({"proof": p})
                        return
                self._send_json({"error": "proof not found"}, 404)
                return

        self._send_json({"error": "not found", "path": path}, 404)

    def _static(self, path: str) -> None:
        rel = path.lstrip("/").replace("\\", "/")
        # strip query from static path if any leaked
        rel = rel.split("?", 1)[0]
        if ".." in rel.split("/"):
            self._send(403, b"forbidden", "text/plain")
            return
        full = (STATIC_DIR / rel).resolve()
        try:
            full.relative_to(STATIC_DIR.resolve())
        except ValueError:
            self._send(403, b"forbidden", "text/plain")
            return
        if not full.exists() or not full.is_file():
            self._send(404, b"not found", "text/plain")
            return
        ctype = mimetypes.guess_type(str(full))[0] or "application/octet-stream"
        if full.suffix == ".js":
            ctype = "application/javascript; charset=utf-8"
        elif full.suffix == ".css":
            ctype = "text/css; charset=utf-8"
        elif full.suffix == ".html":
            ctype = "text/html; charset=utf-8"
        data = full.read_bytes()
        self._send(200, data, ctype)


def _guess_lan_ips() -> list[str]:
    """Best-effort non-loopback IPv4 addresses for VM→host access hints."""
    import socket

    found: list[str] = []
    try:
        # UDP connect trick — no packets need to be sent successfully
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                found.append(ip)
        finally:
            s.close()
    except Exception:
        pass
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127.") and ip not in found:
                found.append(ip)
    except Exception:
        pass
    return found


def run_server(
    host: str = "127.0.0.1",
    port: int = 8787,
    *,
    open_browser: bool = True,
    refresh: bool = True,
) -> None:
    if refresh:
        print(f"[dashboard] indexing {OUTPUT_DIR} …")
        idx = _force_rebuild()
        print(
            f"[dashboard] {idx.get('target_count', 0)} target(s), "
            f"{idx.get('finding_count', 0)} recon record(s)  "
            f"fp={idx.get('output_fingerprint')}"
        )
    else:
        _get_index(force=False)

    httpd = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"[dashboard] listening on {host}:{port}")
    print(f"[dashboard] local:    http://127.0.0.1:{port}/")
    if host in ("0.0.0.0", "::", ""):
        lan = _guess_lan_ips()
        if lan:
            for ip in lan[:4]:
                print(f"[dashboard] from host: http://{ip}:{port}/  (use this from Windows host / LAN)")
        else:
            print(
                f"[dashboard] from host: http://<VM_IP>:{port}/  "
                "(find VM IP with ip a / ipconfig)"
            )
        print(
            "[dashboard] note: allow TCP "
            f"{port} in the VM firewall if the host cannot connect"
        )
    else:
        print(f"[dashboard] UI → http://{host}:{port}/")
    print("[dashboard] reconkit dashboard — scan tracker + findings + inbox + proofs")
    print("[dashboard] inbox:    GET /api/inbox?target=…")
    print("[dashboard] scan:     GET /api/scan?target=…")
    print("[dashboard] live poll: UI watches /api/status — new scans auto-reload")
    print("[dashboard] reindex:  POST /api/reindex  or REINDEX button")
    print(
        "[dashboard] default bind is 127.0.0.1 — pass --host 0.0.0.0 for LAN/VM access. "
        "Do not expose to the public internet."
    )
    print("[dashboard] Ctrl+C to stop")
    # Prefer opening loopback in a local browser (0.0.0.0 is not a valid browse URL)
    browse_url = f"http://127.0.0.1:{port}/"
    if open_browser:
        try:
            webbrowser.open(browse_url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[dashboard] stopped")
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="reconkit cyber dashboard (local / VM)")
    p.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default 127.0.0.1 localhost-only). "
             "Use 0.0.0.0 to reach the UI from a VM host / LAN.",
    )
    p.add_argument("--port", type=int, default=8787, help="Port (default 8787)")
    p.add_argument("--no-browser", action="store_true", help="Do not open a browser tab")
    p.add_argument("--no-refresh", action="store_true", help="Skip reindex on start")
    args = p.parse_args(argv)
    run_server(
        host=args.host,
        port=args.port,
        open_browser=not args.no_browser,
        refresh=not args.no_refresh,
    )


if __name__ == "__main__":
    main()
