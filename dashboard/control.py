"""Background scan control for the local dashboard (scope-gated)."""

from __future__ import annotations

import threading
from typing import Any

_LOCK = threading.Lock()
_THREAD: threading.Thread | None = None
_STATE: dict[str, Any] = {
    "busy": False,
    "target": "",
    "modules": "",
    "error": "",
}


def status() -> dict[str, Any]:
    from run_control import CONTROL
    with _LOCK:
        st = dict(_STATE)
    st["control"] = CONTROL.status()
    st["label"] = CONTROL.label()
    try:
        from live_mission import read_live
        st["live"] = read_live()
    except Exception:
        st["live"] = {}
    return st


def pause() -> dict[str, Any]:
    from run_control import CONTROL
    CONTROL.pause()
    return status()


def resume() -> dict[str, Any]:
    from run_control import CONTROL
    CONTROL.resume()
    return status()


def stop() -> dict[str, Any]:
    from run_control import CONTROL
    n = CONTROL.stop()
    st = status()
    st["killed"] = n
    return st


def start_scan(*, target: str, modules: str = "quick", source: str = "dashboard") -> dict[str, Any]:
    """Start reconkit.cmd_run in a daemon thread. One scan at a time."""
    global _THREAD
    target = (target or "").strip()
    if not target:
        return {"ok": False, "error": "target required"}

    import reconkit as rk

    if not rk.in_scope(target):
        return {
            "ok": False,
            "error": f"'{target}' is not in scope. Add it with: python reconkit.py scope add {target}",
        }

    with _LOCK:
        if _STATE["busy"] or (_THREAD is not None and _THREAD.is_alive()):
            return {"ok": False, "error": "a scan is already running", **status()}
        _STATE.update({"busy": True, "target": target, "modules": modules, "error": ""})

    if modules in ("", "quick"):
        mod_csv = "subdomains,dns,httpprobe"
    elif modules in ("all", "full"):
        mod_csv = "all"
    else:
        mod_csv = modules

    def _run() -> None:
        global _THREAD
        try:
            ns = type("Args", (), {"target": target, "modules": mod_csv, "source": source})()
            rk.load_secrets_env()
            rk.cmd_run(ns)
        except SystemExit as e:
            with _LOCK:
                _STATE["error"] = f"exit {e.code}"
        except Exception as e:
            with _LOCK:
                _STATE["error"] = f"{type(e).__name__}: {e}"
        finally:
            with _LOCK:
                _STATE["busy"] = False

    t = threading.Thread(target=_run, name="reconkit-dash-run", daemon=True)
    _THREAD = t
    t.start()
    return {"ok": True, "target": target, "modules": mod_csv, **status()}
