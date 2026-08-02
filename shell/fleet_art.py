"""ASCII art for console banner + optional dashboard assets (v3.0.0).

Console banner: cyberwarfare theme (pure ASCII, red/black friendly).
Per-module names remain available for phase headers / fleet roster.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Cyberwarfare console banner
# ---------------------------------------------------------------------------

RECONKIT_WORDMARK = r"""
 ____  _____ ____ ___  _   _ _  _____ _____
|  _ \| ____/ ___/ _ \| \ | | |/ /_ _|_   _|
| |_) |  _|| |  | | | |  \| | ' / | |  | |
|  _ <| |__| |__| |_| | |\  | . \ | |  | |
|_| \_\_____\____\___/|_| \_|_|\_\___| |_|
""".strip("\n")

# Compact cyberwarfare frame (no spacedock / no starships)
CYBER_BANNER = r"""
  .--------------------------------------------------------------.
  |  [//]  CYBERWARFARE  OPS  NODE                               |
  |  >_  passive recon  ·  detection only  ·  authorized scope   |
  |  [####------]  channel:SECURE  ·  mode:STEALTH               |
  '--------------------------------------------------------------'
""".strip("\n")

CYBER_SCAN_LINES = [
    "  > syncing threat intel bus...",
    "  > scope gate online",
    "  > sensor mesh armed",
    "  > ready for orders  ·  type /help",
]

# API compat — empty / minimal so UI can skip large dock art
FLAGSHIP = ""
SPACEDOCK = ""  # removed from console + default UI
SPACEDOCK_MINI: list[str] = []
SPACEDOCK_FRAMES: list[list[str]] = [[]]
STARFLEET_DELTA = ""
STAR_TREK_WORDMARK = RECONKIT_WORDMARK

# ---------------------------------------------------------------------------
# Module → unit name (phase headers / roster — not hull ASCII)
# ---------------------------------------------------------------------------

MODULE_SHIP_META: dict[str, tuple[str, str]] = {
    "subdomains": ("NODE PATHFINDER", "Scout"),
    "dns": ("NODE NAVIGATOR", "Science"),
    "httpprobe": ("NODE SENSOR", "Probe"),
    "tls": ("NODE CIPHER", "Escort"),
    "crawl": ("NODE SPIDER", "Explorer"),
    "js": ("NODE ARCHIVE", "Intel"),
    "params": ("NODE KEYMASTER", "Ops"),
    "content": ("NODE DIG", "Survey"),
    "xss": ("NODE MIRROR", "Tactical"),
    "sqli": ("NODE ORACLE", "Tactical"),
    "ssrf_ssti": ("NODE WORMHOLE", "Tactical"),
    "nuclei": ("NODE STRIKE", "Battleship"),
    "cloud": ("NODE NEBULA", "Explorer"),
    "screenshots": ("NODE VIEWSCREEN", "Support"),
    "pipeline": ("OPS COMMAND", "Flag"),
    "default": ("NODE RECON", "Utility"),
}

# No multi-line hull art on console (kept empty for API callers)
MODULE_SHIP_ART: dict[str, str] = {k: "" for k in MODULE_SHIP_META}


def ship_lines(module: str) -> list[str]:
    key = (module or "default").lower().strip()
    art = MODULE_SHIP_ART.get(key, "")
    return art.splitlines() if art else []


def ship_meta(module: str) -> tuple[str, str]:
    key = (module or "default").lower().strip()
    return MODULE_SHIP_META.get(key, MODULE_SHIP_META["default"])
