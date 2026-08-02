"""
Tool layer: run reconkit stages and summarize outputs for agents.

Imports reconkit as a sibling module so we reuse the exact same pipeline,
scope gate, and PATH setup — no duplicate tool wrappers.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Callable

from .state import MODULE_DEPS, MODULE_OUTPUTS, ReconState, summarize_file

# --------------------------------------------------------------------------- #
# Load reconkit.py from the parent directory (same folder as this package)
# --------------------------------------------------------------------------- #

_RECONKIT_PATH = Path(__file__).resolve().parent.parent / "reconkit.py"
_rk = None


def get_reconkit():
    """Lazy-load reconkit so importing agents doesn't always pull it in."""
    global _rk
    if _rk is not None:
        return _rk
    if not _RECONKIT_PATH.exists():
        raise FileNotFoundError(f"reconkit.py not found at {_RECONKIT_PATH}")
    spec = importlib.util.spec_from_file_location("reconkit", _RECONKIT_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("Could not load reconkit.py")
    mod = importlib.util.module_from_spec(spec)
    # Ensure sibling imports / name resolution work if reconkit ever needs them
    sys.modules["reconkit"] = mod
    spec.loader.exec_module(mod)
    _rk = mod
    return mod


# Map module name → callable that runs the stage with correct args
def _stage_runners(rk, target: str, outdir: Path) -> dict[str, Callable[[], Any]]:
    subs = outdir / "subdomains.txt"
    alive = outdir / "alive.txt"
    urls = outdir / "urls.txt"
    wordlist = rk.default_content_wordlist()

    def ensure_subs() -> Path:
        if not subs.exists():
            subs.write_text(target + "\n", encoding="utf-8")
        return subs

    def ensure_alive() -> Path:
        if not alive.exists():
            alive.write_text("", encoding="utf-8")
        return alive

    def ensure_urls() -> Path:
        if not urls.exists():
            urls.write_text("", encoding="utf-8")
        return urls

    return {
        "subdomains": lambda: rk.stage_subdomains(target, outdir),
        "dns": lambda: rk.stage_dns(target, outdir, ensure_subs()),
        "httpprobe": lambda: rk.stage_httpprobe(ensure_subs(), outdir),
        "tls": lambda: rk.stage_tls(ensure_alive(), outdir),
        "crawl": lambda: rk.stage_crawl(ensure_alive(), outdir),
        "js": lambda: rk.stage_js(ensure_urls(), outdir),
        "params": lambda: rk.stage_params(ensure_urls(), outdir),
        "content": lambda: rk.stage_content_discovery(ensure_alive(), outdir, wordlist),
        "xss": lambda: rk.stage_xss(ensure_urls(), outdir),
        "sqli": lambda: rk.stage_sqli(ensure_urls(), outdir),
        "ssrf_ssti": lambda: rk.stage_ssrf_ssti(ensure_urls(), outdir),
        "nuclei": lambda: rk.stage_nuclei(ensure_alive(), ensure_subs(), outdir),
        "cloud": lambda: rk.stage_cloud(ensure_urls(), outdir),
        "screenshots": lambda: rk.stage_screenshots(ensure_alive(), outdir),
    }


def require_scope(target: str) -> None:
    rk = get_reconkit()
    rk.load_secrets_env()
    rk.require_scope_or_exit(target)


def prepare_outdir(target: str) -> Path:
    rk = get_reconkit()
    rk.ensure_dirs()
    outdir = rk.OUTPUT_DIR / target.replace("*", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def list_modules() -> list[str]:
    rk = get_reconkit()
    return list(rk.ALL_MODULES)


def module_descriptions() -> dict[str, str]:
    rk = get_reconkit()
    return dict(rk.MODULE_DESCRIPTIONS)


def run_module(module: str, target: str, outdir: Path) -> dict[str, Any]:
    """
    Execute a single reconkit stage. Returns a result dict with success flag
    and output file summaries.
    """
    rk = get_reconkit()
    all_mods = set(rk.ALL_MODULES)
    if module not in all_mods:
        return {
            "module": module,
            "success": False,
            "error": f"Unknown module '{module}'. Valid: {', '.join(sorted(all_mods))}",
        }

    runners = _stage_runners(rk, target, outdir)
    runner = runners[module]

    try:
        result = rk.run_stage(module, outdir, runner)
    except SystemExit as e:
        return {"module": module, "success": False, "error": f"SystemExit: {e}"}
    except Exception as e:
        return {"module": module, "success": False, "error": str(e)}

    outputs = collect_module_outputs(module, outdir)
    return {
        "module": module,
        "success": True,
        "result": str(result) if result is not None else None,
        "outputs": outputs,
    }


def run_modules(modules: list[str], target: str, outdir: Path, state: ReconState) -> list[dict]:
    results = []
    # Publish full planned module list so the dashboard shows all tiles
    try:
        from live_mission import start_run
        planned = [m for m in modules if m not in state.completed_modules]
        if not planned:
            planned = list(modules)
        start_run(
            target=target,
            modules=planned,
            outdir=outdir,
            source="agent",
        )
    except Exception:
        pass
    try:
        for m in modules:
            if m in state.completed_modules:
                results.append({
                    "module": m,
                    "success": True,
                    "skipped": True,
                    "reason": "already completed",
                })
                continue
            if not state.deps_satisfied(m):
                missing = [d for d in MODULE_DEPS.get(m, []) if d not in state.completed_modules]
                results.append({
                    "module": m,
                    "success": False,
                    "error": f"Prerequisites not met: {', '.join(missing)}",
                })
                continue
            res = run_module(m, target, outdir)
            results.append(res)
            if res.get("success"):
                state.mark(m)
                # Store a compact finding blurb
                outs = res.get("outputs") or []
                state.findings[m] = {
                    "files": [o.get("path") for o in outs if o.get("exists")],
                    "highlights": _highlights(outs),
                }
            state.save()
        return results
    finally:
        # Keep mission active between agent steps so the dashboard does not
        # flicker idle while the planner thinks. Orchestrator / shell finish it.
        try:
            from live_mission import mark_stopped, publish
            from run_control import CONTROL
            if CONTROL.is_stopped():
                mark_stopped()
            else:
                publish({
                    "active": True,
                    "status": "running",
                    "current_tool": "",
                    "message": "agent batch done · awaiting next plan",
                    "current_module": "",
                })
        except Exception:
            pass


def collect_module_outputs(module: str, outdir: Path) -> list[dict[str, Any]]:
    names = list(MODULE_OUTPUTS.get(module, []))
    if module == "nuclei":
        names = [p.name for p in sorted(outdir.glob("nuclei_*.txt"))]
    if module == "content":
        # also pick up ffuf jsons
        names = names + [p.name for p in sorted(outdir.glob("ffuf_*.json"))[:5]]

    results = []
    for name in names:
        p = outdir / name
        results.append(summarize_file(p))
    return results


def _highlights(outputs: list[dict]) -> list[str]:
    notes = []
    for o in outputs:
        if not o.get("exists"):
            continue
        if o.get("empty"):
            notes.append(f"{o['path']}: empty")
            continue
        lines = o.get("lines")
        if lines is not None:
            notes.append(f"{o['path']}: {lines} lines")
        if o.get("interesting_keywords"):
            notes.append(f"{o['path']} keywords: {', '.join(o['interesting_keywords'])}")
    return notes
