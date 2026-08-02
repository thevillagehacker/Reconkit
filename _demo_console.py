#!/usr/bin/env python3
"""Print a demo of the Starfleet bridge console (banner, prompt, fleet, sample run)."""
from __future__ import annotations

import os
import time

os.environ.setdefault("FORCE_COLOR", "1")
# Keep animation short for demos (still shows colorized base)
os.environ.setdefault("RECONKIT_NO_ANIM", "0")

from shell import theme
from progress_ui import (
    FLEET_SHIPS,
    PHASE_TITLE,
    SHIP_ART,
    _print_ops_banner,
    cyber_bar,
    fleet_ship_line,
    print_module_ship_banner,
)
import reconkit as rk


def main() -> None:
    print("=" * 72)
    print("1) SHELL BANNER (Star Trek logo + spacedock + fleet roster)")
    print("=" * 72)
    theme.print_banner("3.0.0", animate=False)

    print("=" * 72)
    print("2) LIVE PROMPT (what appears at the input line)")
    print("=" * 72)
    print("--- with sector set ---")
    print(theme.make_prompt("discover.com", 1, "normal"), end="")
    print(" /run discover.com --modules subdomains,dns,httpprobe")
    print()
    print("--- no sector yet ---")
    print(theme.make_prompt("", 1, "normal"), end="")
    print(" /scope add discover.com")
    print()

    print("=" * 72)
    print("3) FULL FLEET ROSTER (all recon modules as starships)")
    print("=" * 72)
    print(f"{'MODULE':<14}  {'SHIP':<18}  {'CLASS':<12}  PHASE TITLE")
    print("-" * 72)
    for mod, (ship, klass) in FLEET_SHIPS.items():
        if mod in ("pipeline", "default"):
            continue
        title = PHASE_TITLE.get(mod, "")
        print(f"{mod:<14}  {ship:<18}  {klass:<12}  {title}")
    print()

    print("=" * 72)
    print("4) PER-MODULE SHIP BANNERS (1 asciiart.eu hull per module)")
    print("=" * 72)
    mods = [m for m in SHIP_ART.keys() if m not in ("pipeline", "default")]
    # Sample 4 ships fully; list the rest
    for i, mod in enumerate(mods[:4], 1):
        print_module_ship_banner(mod, index=i, total=len(mods), detail=f"module={mod}", animate=False)
    print("  … remaining modules each get their own unique hull at run time …")
    for mod in mods[4:]:
        ship, klass = FLEET_SHIPS[mod]
        print(f"  ✦ {mod:<12} → {ship}  [{klass}]")
    print()

    print("=" * 72)
    print("5) SAMPLE MISSION RUN (quiet normal verbosity v:1)")
    print("   Unique ship banner per module — no intermediate INFO chatter")
    print("=" * 72)

    rk._PIPELINE = object()
    rk.VERBOSE = 1

    mods = ["subdomains", "dns", "httpprobe"]
    _print_ops_banner("discover.com", mods)

    # --- phase 1: subdomains ---
    print_module_ship_banner("subdomains", index=1, total=3, detail="module=subdomains", animate=False)
    print("  [06:21:49]  ▸  Subdomain enum · discover.com  (8 tools)")
    tools = [
        ("subfinder", "1003", False),
        ("amass", "0", False),
        ("assetfinder", "12", False),
        ("chaos", "113", False),
        ("findomain", "7", False),
        ("crt.sh", "0", False),
        ("wayback", "2", False),
        ("hackertarget", "skip", True),
    ]
    total = len(tools)
    for i, (name, val, skip) in enumerate(tools, 1):
        pct = 100.0 * i / total
        bar = cyber_bar(pct, width=18, color="blue" if skip else "green")
        icon = "–" if skip else "✓"
        print(f"  {icon}  {i}/{total}  {name:<12}  {val:>6}  {bar}  {pct:3.0f}%  00:0{min(i,9)}:1{i%10}")
    print(f"  ✔  {cyber_bar(100, 20, 'green')}  8/8 tools  100%  7 ok · 1 skip  00:02:30")
    print(f"  ✔  {cyber_bar(33, 20, 'green')}  1/3  USS PATHFINDER  150.2s")
    print()

    # --- phase 2: dns ---
    print_module_ship_banner("dns", index=2, total=3, detail="module=dns", animate=False)
    print("  [06:24:20]  ▸  DNS · 1014 host(s)  (2 tools)")
    print(f"  ✓  1/2  dnsx-records    4200  {cyber_bar(50, 18, 'green')}   50%  00:00:45")
    print(f"  ✓  2/2  dnsx-cname         3  {cyber_bar(100, 18, 'green')}  100%  00:00:52")
    print(f"  ✔  {cyber_bar(100, 20, 'green')}  2/2 tools  100%  2 ok  00:00:52")
    print(f"  ✔  {cyber_bar(66, 20, 'green')}  2/3  USS NAVIGATOR  52.1s")
    print()

    # --- phase 3: httpprobe ---
    print_module_ship_banner("httpprobe", index=3, total=3, detail="module=httpprobe", animate=False)
    print("  [06:25:15]  ▸  HTTP probe · 1014 host(s)  (1 tools)")
    print(f"  ✓  1/1  httpx             89  {cyber_bar(100, 18, 'green')}  100%  00:00:18")
    print(f"  ✔  {cyber_bar(100, 20, 'green')}  1/1 tools  100%  1 ok  00:00:18")
    print(f"  ✔  {cyber_bar(100, 20, 'green')}  3/3  USS SENSOR  18.2s")
    print()

    print(
        f"  ✔  {cyber_bar(100, 24, 'green')}  MISSION COMPLETE  3 ships  00:03:41"
        "  → ~/.reconkit/output/discover.com"
    )
    print()
    print("[OK] mission complete  ·  job a1b2c3d4e5")
    print("  → done discover.com modules=subdomains,dns,httpprobe")
    print("  bridge ready  ·  type / for orders  ·  /dashboard viewscreen")
    print()
    print(theme.make_prompt("discover.com", 1, "normal"), end="")
    print()
    print()

    print("=" * 72)
    print("6) DASHBOARD BRIDGE (browser) — same fleet names")
    print("=" * 72)
    print("  Tabs:  MISSION | SENSORS | PROOF LOCKER | TACTICAL MAP | SCIENCE")
    print("  Mission view controls: Restart · Play/Pause · 0.5x 1x 2x 4x 8x · scrubber")
    print("  Panels: chain map · phase activity · live action stream · volume · fleet board")
    print()
    from dashboard.mission import MISSION_PHASES

    print(f"  {'SHIP':<18}  {'CLASS':<12}  {'MODULE':<12}  STAGE  ROLE")
    print("  " + "-" * 70)
    for p in MISSION_PHASES:
        role = (p.get("role") or "")[:40]
        print(
            f"  {p['ship']:<18}  {p['class']:<12}  {p['id']:<12}  "
            f"{p['stage']:<5}  {role}"
        )
    print()
    print("=" * 72)
    print("WHAT IS PRINTED vs HIDDEN at normal verbosity (v:1)")
    print("=" * 72)
    print("  SHOWN:")
    print("    · animated starbase on shell banner")
    print("    · fleet mission box + colorized ship route")
    print("    · unique ship hull banner per module (while running)")
    print("    · tool checklist title + result lines (bar + counts)")
    print("    · phase complete bar · MISSION COMPLETE")
    print("    · WARN / FAIL always")
    print("  HIDDEN (unless /verbose 2 or 3):")
    print("    · intermediate [INFO] / most [OK] chatter")
    print("    · $ command echoes while HUD active")
    print("    · full tool stdout (needs /verbose 3 live)")
    print()


if __name__ == "__main__":
    main()
