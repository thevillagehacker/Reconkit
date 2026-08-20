"""ASCII banner + per-module labels for the console and dashboard."""

from __future__ import annotations

RECONKIT_WORDMARK = r"""
 ____  _____ ____ ___  _   _ _  _____ _____
|  _ \| ____/ ___/ _ \| \ | | |/ /_ _|_   _|
| |_) |  _|| |  | | | |  \| | ' / | |  | |
|  _ <| |__| |__| |_| | |\  | . \ | |  | |
|_| \_\_____\____\___/|_| \_|_|\_\___| |_|
""".strip("\n")

CYBER_BANNER = r"""
  .--------------------------------------------------------------.
  |  RECONKIT  ·  authorized recon                               |
  |  passive + detection canaries  ·  no exploit frameworks      |
  '--------------------------------------------------------------'
""".strip("\n")

CYBER_SCAN_LINES = [
    "  > loading config...",
    "  > scope gate online",
    "  > ready  ·  type /help",
]

FLAGSHIP = ""
SPACEDOCK = ""
SPACEDOCK_MINI: list[str] = []
SPACEDOCK_FRAMES: list[list[str]] = [[]]
# Formal recon labels (kept as MODULE_SHIP_META for older imports)
MODULE_META: dict[str, tuple[str, str]] = {
    "subdomains": ("Subdomain enum", "passive"),
    "permute": ("DNS permutations", "passive"),
    "dns": ("DNS records", "passive"),
    "ports": ("Port probe", "active"),
    "httpprobe": ("HTTP probe", "active"),
    "tls": ("TLS fingerprint", "active"),
    "wellknown": ("Well-known paths", "discovery"),
    "crawl": ("URL crawl", "discovery"),
    "js": ("JavaScript", "discovery"),
    "jsintel": ("JS intel", "discovery"),
    "params": ("Parameters", "discovery"),
    "apis": ("API surface", "discovery"),
    "content": ("Content discovery", "discovery"),
    "bypass403": ("403 bypass", "detection"),
    "gfextra": ("gf extras", "discovery"),
    "xss": ("XSS canaries", "detection"),
    "sqli": ("SQLi canaries", "detection"),
    "ssrf_ssti": ("SSRF / SSTI", "detection"),
    "redirect": ("Open redirect", "detection"),
    "cors": ("CORS", "detection"),
    "graphql": ("GraphQL", "detection"),
    "nuclei": ("Nuclei templates", "detection"),
    "cloud": ("Cloud assets", "detection"),
    "takeover_plus": ("Takeover extras", "detection"),
    "osint": ("Scoped OSINT", "passive"),
    "gitrecon": ("Git recon", "passive"),
    "screenshots": ("Screenshots", "visual"),
    "pipeline": ("Pipeline", "control"),
    "default": ("Recon", "utility"),
}
MODULE_SHIP_META = MODULE_META
MODULE_SHIP_ART: dict[str, str] = {k: "" for k in MODULE_META}


def ship_lines(module: str) -> list[str]:
    return []


def ship_meta(module: str) -> tuple[str, str]:
    key = (module or "default").lower().strip()
    return MODULE_META.get(key, MODULE_META["default"])
