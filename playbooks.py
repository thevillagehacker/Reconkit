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
        "description": "Subdomains + DNS CNAME candidates + extra takeover surface + HTTP",
        "modules": ["subdomains", "dns", "httpprobe", "takeover_plus"],
    },
    "js-deep": {
        "description": "Live hosts → crawl → JS secrets + sourcemaps/routes + params",
        "modules": ["httpprobe", "crawl", "js", "jsintel", "params"],
    },
    "api-surface": {
        "description": "API/OpenAPI/GraphQL harvest + IDOR-shaped params + CORS",
        "modules": ["httpprobe", "crawl", "jsintel", "params", "apis", "graphql", "cors", "nuclei"],
    },
    "vuln-pass": {
        "description": "Detection pass: xss, sqli, ssrf/ssti, redirect, cors, graphql, nuclei, cloud",
        "modules": ["xss", "sqli", "ssrf_ssti", "redirect", "cors", "graphql", "nuclei", "cloud"],
    },
    "content-light": {
        "description": "Well-known paths + sensitive paths + 401/403 header probes",
        "modules": ["httpprobe", "wellknown", "content", "bypass403"],
    },
    "full": {
        "description": "All reconkit modules",
        "modules": ["all"],
    },
    "passive": {
        "description": "Lower noise: subdomains, dns, httpprobe, tls, wellknown, crawl (no fuzz/xss)",
        "modules": ["subdomains", "dns", "httpprobe", "tls", "wellknown", "crawl"],
    },
    "ports-hint": {
        "description": "Subdomains + DNS + in-scope naabu connect-scan + HTTP probe",
        "modules": ["subdomains", "dns", "ports", "httpprobe", "tls"],
    },
    "auth-surface": {
        "description": (
            "Authenticated recon (set /session first): crawl + JS intel + APIs + 403 bypass. "
            "Then /prove run --technique idor_session_diff after cookie-B is set."
        ),
        "modules": ["httpprobe", "crawl", "js", "jsintel", "apis", "bypass403"],
    },
    "hunter": {
        "description": "Hunter extras: permute, ports, well-known, JS intel, APIs, 403, gf extras, takeover+",
        "modules": [
            "permute", "ports", "wellknown", "jsintel", "apis",
            "bypass403", "gfextra", "redirect", "cors", "graphql", "takeover_plus",
        ],
    },
    "prove-prep": {
        "description": (
            "Detection surface for later /prove: crawl + xss + sqli + ssrf_ssti + "
            "redirect/cors/graphql + nuclei + cloud. Then: /findings reindex && /prove queue && /prove run"
        ),
        "modules": [
            "httpprobe", "crawl", "xss", "sqli", "ssrf_ssti",
            "redirect", "cors", "graphql", "nuclei", "cloud",
        ],
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
