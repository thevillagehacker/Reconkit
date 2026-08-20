"""
Disk-backed live scan tracker for the dashboard.

Writers (shell / reconkit / agents) publish phase + tool progress.
Readers (dashboard, separate process) poll the newest file.

Writes to several paths so a VM scan and a Windows/host dashboard still
see updates when they share ~/.reconkit or output/ via mount/sync:

  1) $RECONKIT_HOME/live_mission.json  (if set)
  2) ~/.reconkit/live_mission.json
  3) ~/.reconkit/output/.live_mission.json
  4) <target outdir>/.live_mission.json  (when known)
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()


def _home_reconkit() -> Path:
    env = (os.environ.get("RECONKIT_HOME") or "").strip()
    if env:
        return Path(env).expanduser()
    try:
        from findings.store import BASE_DIR  # type: ignore
        return Path(BASE_DIR)
    except Exception:
        pass
    try:
        import reconkit as rk
        return Path(rk.BASE_DIR)
    except Exception:
        return Path.home() / ".reconkit"


def state_paths(outdir: str | Path | None = None) -> list[Path]:
    """Ordered unique paths we write/read (first is primary)."""
    home = _home_reconkit()
    paths: list[Path] = [
        home / "live_mission.json",
        home / "output" / ".live_mission.json",
    ]
    if outdir:
        try:
            paths.append(Path(outdir) / ".live_mission.json")
        except Exception:
            pass
    # De-dupe while preserving order
    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        key = str(p.resolve()) if p.parent.exists() else str(p)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


LIVE_PATH = _home_reconkit() / "live_mission.json"

_state: dict[str, Any] = {
    "active": False,
    "status": "idle",  # idle | running | paused | stopping | complete | failed | stopped
    "target": "",
    "modules": [],
    "completed": [],
    "current_module": "",
    "current_index": 0,
    "total": 0,
    "current_tool": "",
    "host_current": 0,
    "host_total": 0,
    "message": "",
    "started_at": 0.0,
    "updated_at": 0.0,
    "finished_at": 0.0,
    "elapsed_s": 0.0,
    "control": "idle",
    "outdir": "",
    "source": "",  # pipeline | stage | agent
}


def live_path() -> Path:
    return state_paths()[0]


def _control_status() -> str:
    try:
        from run_control import CONTROL
        return CONTROL.status()
    except Exception:
        return "unknown"


def _write_all(payload: dict[str, Any]) -> None:
    data = json.dumps(payload, indent=2, ensure_ascii=False)
    for path in state_paths(payload.get("outdir") or None):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(data, encoding="utf-8")
            tmp.replace(path)
        except Exception:
            # Best-effort — never break the scan for dashboard telemetry
            pass


def snapshot() -> dict[str, Any]:
    with _LOCK:
        return dict(_state)


def publish(partial: dict[str, Any] | None = None) -> dict[str, Any]:
    """Merge partial into in-memory state and flush to all paths."""
    with _LOCK:
        if partial:
            # Never clobber non-empty modules/target with empty values unless explicit clear
            for k, v in partial.items():
                if k in ("modules", "completed") and v is None:
                    continue
                if k in ("modules", "target", "outdir") and v in ("", [], None):
                    if _state.get(k):
                        continue
                _state[k] = v
        _state["updated_at"] = time.time()
        if _state.get("started_at"):
            _state["elapsed_s"] = round(time.time() - float(_state["started_at"]), 1)
        try:
            ctrl = _control_status()
            _state["control"] = ctrl
            if ctrl == "paused" and _state.get("active"):
                _state["status"] = "paused"
            elif ctrl == "stopped" and _state.get("active"):
                _state["status"] = "stopping"
        except Exception:
            pass
        out = dict(_state)
    _write_all(out)
    return out


def start_run(
    *,
    target: str,
    modules: list[str],
    outdir: str | Path = "",
    source: str = "pipeline",
) -> dict[str, Any]:
    mods = [m.strip() for m in modules if m and m.strip()]
    od = str(outdir or "")
    return publish({
        "active": True,
        "status": "running",
        "target": target or "",
        "modules": mods,
        "completed": [],
        "current_module": "",
        "current_index": 0,
        "total": len(mods),
        "current_tool": "",
        "host_current": 0,
        "host_total": 0,
        "message": f"scan start · {len(mods)} phase(s)",
        "started_at": time.time(),
        "finished_at": 0.0,
        "elapsed_s": 0.0,
        "outdir": od,
        "source": source,
    })


def begin_phase(
    name: str,
    index: int | None = None,
    total: int | None = None,
    *,
    outdir: str | Path = "",
) -> dict[str, Any]:
    """Mark a phase running. Index/total auto-derived from modules list if omitted."""
    with _LOCK:
        mods = list(_state.get("modules") or [])
        if name and name not in mods:
            mods.append(name)
            _state["modules"] = mods
        if total is None:
            total = max(len(mods), int(_state.get("total") or 0), 1)
        if index is None:
            # 1-based index from modules order
            try:
                index = mods.index(name) + 1
            except ValueError:
                index = int(_state.get("current_index") or 0) + 1
        if outdir:
            _state["outdir"] = str(outdir)
        if not _state.get("started_at"):
            _state["started_at"] = time.time()
        if not _state.get("active"):
            _state["active"] = True
            _state["status"] = "running"
    return publish({
        "active": True,
        "status": "running",
        "current_module": name,
        "current_index": int(index or 0),
        "total": int(total or 0),
        "current_tool": "",
        "host_current": 0,
        "host_total": 0,
        "message": f"phase {index}/{total} · {name}",
    })


def end_phase(name: str, *, elapsed: float | None = None) -> dict[str, Any]:
    with _LOCK:
        completed = list(_state.get("completed") or [])
        if name and name not in completed:
            completed.append(name)
        _state["completed"] = completed
        _state["current_tool"] = ""
        _state["message"] = f"phase complete · {name}" + (
            f" · {elapsed:.1f}s" if elapsed is not None else ""
        )
        _state["updated_at"] = time.time()
        if _state.get("started_at"):
            _state["elapsed_s"] = round(time.time() - float(_state["started_at"]), 1)
        out = dict(_state)
    _write_all(out)
    return out


def set_tool(name: str, *, detail: str = "") -> dict[str, Any]:
    msg = f"tool · {name}" + (f" · {detail}" if detail else "")
    if _state.get("current_module"):
        msg = f"{_state['current_module']} · {msg}"
    return publish({
        "active": True,
        "status": "running",
        "current_tool": name or "",
        "message": msg,
    })


def set_hosts(*, current: int | None = None, total: int | None = None) -> None:
    partial: dict[str, Any] = {}
    if current is not None:
        partial["host_current"] = int(current)
    if total is not None:
        partial["host_total"] = int(total)
    if partial:
        # Keep active so long-running tools still show as live
        if _state.get("current_module") or _state.get("modules"):
            partial.setdefault("active", True)
            if _state.get("status") in ("idle", "", None):
                partial["status"] = "running"
        publish(partial)


def finish_run(*, ok: bool = True, outdir: str = "", message: str = "") -> dict[str, Any]:
    if not message:
        message = (
            ("scan complete" + (f" · {outdir}" if outdir else ""))
            if ok
            else "scan failed"
        )
    return publish({
        "active": False,
        "status": "complete" if ok else "failed",
        "current_module": "",
        "current_tool": "",
        "message": message,
        "finished_at": time.time(),
        "host_current": 0,
        "host_total": 0,
    })


def mark_stopped(message: str = "stopped by operator (/stop)") -> dict[str, Any]:
    """Stop without wiping modules/target (dashboard still shows last run)."""
    return publish({
        "active": False,
        "status": "stopped",
        "current_tool": "",
        "message": message,
        "finished_at": time.time(),
    })


def _read_path(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def read_live() -> dict[str, Any]:
    """Read newest live_mission.json across known paths (dashboard process)."""
    candidates: list[tuple[float, dict[str, Any], str]] = []
    for path in state_paths():
        data = _read_path(path)
        if not data:
            continue
        # Prefer updated_at; fall back to mtime
        updated = float(data.get("updated_at") or 0)
        try:
            mtime = path.stat().st_mtime
        except Exception:
            mtime = 0.0
        score = max(updated, mtime)
        data = dict(data)
        data["_path"] = str(path)
        candidates.append((score, data, str(path)))

    # Also scan output/*/.live_mission.json for any target (freshness)
    try:
        out_root = _home_reconkit() / "output"
        if out_root.is_dir():
            for p in out_root.glob("*/.live_mission.json"):
                data = _read_path(p)
                if not data:
                    continue
                updated = float(data.get("updated_at") or 0)
                try:
                    mtime = p.stat().st_mtime
                except Exception:
                    mtime = 0.0
                data = dict(data)
                data["_path"] = str(p)
                candidates.append((max(updated, mtime), data, str(p)))
    except Exception:
        pass

    if not candidates:
        return {
            "active": False,
            "status": "idle",
            "target": "",
            "modules": [],
            "completed": [],
            "current_module": "",
            "current_index": 0,
            "total": 0,
            "current_tool": "",
            "host_current": 0,
            "host_total": 0,
            "message": "no live scan file — start /run or /agent",
            "updated_at": 0,
            "stale": True,
            "_path": str(live_path()),
        }

    candidates.sort(key=lambda x: x[0], reverse=True)
    data = candidates[0][1]
    updated = float(data.get("updated_at") or 0)
    # Active runs go stale after 5 minutes without heartbeats
    if data.get("active") and updated and (time.time() - updated) > 300:
        data["stale"] = True
        data["status"] = "stale"
        data["message"] = (data.get("message") or "") + " · heartbeat stale"
    else:
        data["stale"] = False
    data["age_s"] = round(time.time() - updated, 1) if updated else None
    return data
