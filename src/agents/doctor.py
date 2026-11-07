"""
Tool-failure doctor (Tier B) — diagnose empty stages / recent tool errors.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    import reconkit as rk
    DEBUG_LOG = rk.DEBUG_LOG
    OUTPUT_DIR = rk.OUTPUT_DIR
except Exception:
    DEBUG_LOG = Path.home() / ".reconkit" / "logs" / "debug.log"
    OUTPUT_DIR = Path.home() / ".reconkit" / "output"


_HINTS = [
    (re.compile(r"rate.?limit|429|too many requests", re.I),
     "Possible rate limit — slow down, add API keys, or re-run later."),
    (re.compile(r"unauthorized|401|403|forbidden|api.?key|invalid key", re.I),
     "Auth/API key issue — check /keys list and provider config for that tool."),
    (re.compile(r"not found|no such file|cannot find|is not recognized", re.I),
     "Tool or file missing — run /verify and /setup; ensure PATH includes go/bin."),
    (re.compile(r"timeout|timed out|deadline exceeded", re.I),
     "Timeout — raise tool timeout or check network/VPN to the target."),
    (re.compile(r"connection refused|no route to host|network is unreachable", re.I),
     "Network unreachable — check DNS, VPN, firewall, and target availability."),
    (re.compile(r"certificate|ssl|tls", re.I),
     "TLS/certificate noise — often non-fatal; verify with -v 3 if stage empty."),
    (re.compile(r"exit=1|exit=2", re.I),
     "Non-zero exit — re-run with /verbose 3 and inspect stderr in debug.log."),
]


def diagnose_log(max_lines: int = 400) -> list[str]:
    """Return human hints from the tail of debug.log."""
    if not DEBUG_LOG.exists():
        return [f"No debug log yet at {DEBUG_LOG}. Run a scan with /verbose 2+."]
    try:
        text = DEBUG_LOG.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return [f"Could not read {DEBUG_LOG}: {e}"]
    lines = text.splitlines()[-max_lines:]
    tail = "\n".join(lines)
    hints: list[str] = []
    seen: set[str] = set()
    for rx, msg in _HINTS:
        if rx.search(tail) and msg not in seen:
            hints.append(msg)
            seen.add(msg)
    # last few command failures
    fails = [ln for ln in lines if "exit=" in ln and "exit=0" not in ln][-8:]
    if fails:
        hints.append("Recent non-zero exits:")
        hints.extend("  " + f for f in fails)
    if not hints:
        hints.append(
            "No strong failure patterns in recent log. "
            "Empty yield may mean no assets, missing keys (subfinder -all), or filters."
        )
    hints.append(f"Log path: {DEBUG_LOG}")
    return hints


def diagnose_target(target: str) -> dict[str, Any]:
    """Quick disk health for a target output folder."""
    out = OUTPUT_DIR / target.replace("*", "_")
    info: dict[str, Any] = {
        "target": target,
        "outdir": str(out),
        "exists": out.exists(),
        "files": [],
        "missing_core": [],
        "hints": [],
    }
    if not out.exists():
        info["hints"].append("No output folder — run /quick or /run first.")
        return info
    files = sorted(p.name for p in out.iterdir() if p.is_file())
    info["files"] = files[:40]
    for core in ("subdomains.txt", "alive.txt", "urls.txt"):
        p = out / core
        if not p.exists() or p.stat().st_size == 0:
            info["missing_core"].append(core)
    if "subdomains.txt" in info["missing_core"]:
        info["hints"].append("No subdomains — check keys (/keys list) and scope.")
    if "alive.txt" in info["missing_core"]:
        info["hints"].append("No alive hosts — run httpprobe after subdomains.")
    if "urls.txt" in info["missing_core"]:
        info["hints"].append("No URLs — run crawl after httpprobe.")
    info["hints"].extend(diagnose_log()[:5])
    return info
