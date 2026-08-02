"""
Load per-program JSON profiles and apply bounty-oriented score weights.

Active program resolution (first wins):
  1. RECON_PROGRAM env
  2. ~/.reconkit/active_program.txt
  3. \"default\"
"""

from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
PROFILES_DIR = REPO_ROOT / "config" / "programs"
USER_ACTIVE = Path.home() / ".reconkit" / "active_program.txt"

_DEFAULT: dict[str, Any] = {
    "name": "default",
    "display_name": "Default program",
    "max_risk_class": "safe",
    "notable_threshold": 40,
    "bounty_weights": {"default": 1.0},
    "severity_bonus": {},
    "scope_includes": [],
    "scope_excludes": [],
}


def list_profiles() -> list[dict[str, Any]]:
    out = []
    if not PROFILES_DIR.exists():
        return [{"name": "default", "path": str(PROFILES_DIR / "default.json")}]
    for p in sorted(PROFILES_DIR.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            out.append({
                "name": data.get("name") or p.stem,
                "display_name": data.get("display_name") or p.stem,
                "path": str(p),
                "notes": (data.get("notes") or "")[:120],
            })
        except Exception:
            out.append({"name": p.stem, "display_name": p.stem, "path": str(p), "notes": ""})
    return out


def load_profile(name: str | None = None) -> dict[str, Any]:
    name = (name or active_program_name()).strip() or "default"
    path = PROFILES_DIR / f"{name}.json"
    data = deepcopy(_DEFAULT)
    data["name"] = name
    if path.exists():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                data.update(raw)
        except Exception:
            pass
    data["name"] = data.get("name") or name
    return data


def active_program_name() -> str:
    env = (os.getenv("RECON_PROGRAM") or "").strip()
    if env:
        return env
    try:
        if USER_ACTIVE.exists():
            t = USER_ACTIVE.read_text(encoding="utf-8").strip()
            if t:
                return t
    except Exception:
        pass
    return "default"


def set_active_program(name: str) -> Path:
    name = name.strip()
    USER_ACTIVE.parent.mkdir(parents=True, exist_ok=True)
    USER_ACTIVE.write_text(name + "\n", encoding="utf-8")
    os.environ["RECON_PROGRAM"] = name
    return USER_ACTIVE


def get_active_profile() -> dict[str, Any]:
    return load_profile(active_program_name())


def weight_category_for_finding(d: dict[str, Any]) -> str:
    """Map a finding to a bounty weight category key."""
    mod = str(d.get("module") or "").lower()
    ftype = str(d.get("ftype") or "").lower()
    blob = " ".join(
        str(d.get(k, "")) for k in ("title", "asset", "evidence", "module")
    ).lower()
    tags = " ".join(str(t) for t in (d.get("tags") or [])).lower()
    blob = blob + " " + tags

    checks = [
        ("takeover", ("takeover", "cname")),
        ("secret", ("secret", "akia", "private key", "token", "webhook")),
        ("rce", ("rce", "remote code", "command injection")),
        ("ssti", ("ssti", "template inject")),
        ("ssrf", ("ssrf", "169.254", "metadata")),
        ("sqli", ("sqli", "sql injection")),
        ("xss", ("xss", "dalfox", "cross-site")),
        ("idor", ("idor", "bola", "broken object")),
        ("auth", ("auth", "authz", "privilege", "jwt")),
        ("cloud", ("s3", "cloud", "firebase", "azure", "gcp")),
        ("nuclei", ("nuclei", "cve-")),
    ]
    for cat, kws in checks:
        if any(k in blob for k in kws):
            return cat
    if mod in ("xss", "sqli", "ssrf_ssti", "nuclei", "cloud", "dns", "js"):
        return {
            "xss": "xss",
            "sqli": "sqli",
            "ssrf_ssti": "ssrf",
            "nuclei": "nuclei",
            "cloud": "cloud",
            "dns": "takeover" if "takeover" in blob or "cname" in blob else "default",
            "js": "secret" if ftype == "secret" else "default",
        }.get(mod, "default")
    if ftype == "secret":
        return "secret"
    if ftype == "vuln":
        return "nuclei"
    if ftype in ("info",):
        return "info"
    return "default"


def apply_program_score(base_score: int, d: dict[str, Any], profile: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    """
    Apply program weights to a base recon score.
    Returns (weighted_score, meta).
    """
    prof = profile or get_active_profile()
    weights = prof.get("bounty_weights") or {}
    sev_bonus = prof.get("severity_bonus") or {}
    cat = weight_category_for_finding(d)
    w = float(weights.get(cat, weights.get("default", 1.0)) or 1.0)
    sev = str(d.get("severity") or "info").lower()
    sb = float(sev_bonus.get(sev, 1.0) or 1.0)
    # soft deprioritize excluded host patterns
    asset = str(d.get("asset") or "") + " " + str(d.get("target") or "")
    for ex in prof.get("scope_excludes") or []:
        if _globish_match(str(ex), asset):
            w *= 0.35
            cat = cat + "+excluded"
            break
    weighted = int(round(base_score * w * sb))
    weighted = max(0, min(weighted, 250))
    meta = {
        "program": prof.get("name"),
        "weight_category": cat,
        "weight": w,
        "severity_bonus": sb,
        "base_score": base_score,
    }
    return weighted, meta


def _globish_match(pattern: str, text: str) -> bool:
    """Simple * wildcard match against text."""
    pat = re.escape(pattern.strip()).replace(r"\*", ".*")
    try:
        return bool(re.search(pat, text, re.I))
    except re.error:
        return pattern.lower() in text.lower()
