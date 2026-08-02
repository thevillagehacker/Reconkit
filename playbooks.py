"""
Named recon playbooks (Tier A) — reusable module recipes.
"""

from __future__ import annotations

from typing import Any

PLAYBOOKS: dict[str, dict[str, Any]] = {
    "quick": {
        "description": "Fast surface: subdomains + DNS + HTTP probe",
        "modules": ["subdomains", "dns", "httpprobe"],
    },
    "takeover-first": {
        "description": "Subdomains + DNS (CNAME takeover candidates) + HTTP",
        "modules": ["subdomains", "dns", "httpprobe"],
    },
    "js-deep": {
        "description": "Live hosts → crawl → JS secrets/endpoints → params",
        "modules": ["httpprobe", "crawl", "js", "params"],
    },
    "api-surface": {
        "description": "Crawl + params + content + nuclei (API-ish surface)",
        "modules": ["httpprobe", "crawl", "params", "content", "nuclei"],
    },
    "vuln-pass": {
        "description": "Detection pass: xss, sqli, ssrf/ssti, nuclei, cloud",
        "modules": ["xss", "sqli", "ssrf_ssti", "nuclei", "cloud"],
    },
    "content-light": {
        "description": "Sensitive paths + light content discovery",
        "modules": ["httpprobe", "content"],
    },
    "full": {
        "description": "All reconkit modules",
        "modules": ["all"],
    },
    "passive": {
        "description": "Lower noise: subdomains, dns, httpprobe, tls, crawl (no fuzz/xss)",
        "modules": ["subdomains", "dns", "httpprobe", "tls", "crawl"],
    },
    "ports-hint": {
        "description": (
            "No dedicated ports module yet — runs discovery set; "
            "use naabu manually on alive hosts if needed"
        ),
        "modules": ["subdomains", "dns", "httpprobe", "tls"],
    },
    # After recon: use /prove (not module list) — documented for hunters
    "prove-prep": {
        "description": (
            "Detection surface for later /prove: crawl + xss + sqli + ssrf_ssti + nuclei + cloud. "
            "Then: /findings reindex && /prove queue && /prove run"
        ),
        "modules": ["httpprobe", "crawl", "xss", "sqli", "ssrf_ssti", "nuclei", "cloud"],
    },
}


def list_playbooks() -> list[dict[str, Any]]:
    return [
        {"name": name, "description": p["description"], "modules": list(p["modules"])}
        for name, p in sorted(PLAYBOOKS.items())
    ]


def get_playbook(name: str) -> dict[str, Any] | None:
    p = PLAYBOOKS.get(name.strip().lower())
    if not p:
        return None
    return {"name": name.strip().lower(), **p}


def modules_csv(name: str) -> str | None:
    p = get_playbook(name)
    if not p:
        return None
    mods = p["modules"]
    if mods == ["all"] or (len(mods) == 1 and mods[0] == "all"):
        return "all"
    return ",".join(mods)
