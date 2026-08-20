"""Load and enforce exploit / prove policy (safe by default)."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
REPO_POLICY = REPO_ROOT / "config" / "exploit_policy.json"

DEFAULT_POLICY: dict[str, Any] = {
    "version": "3.0.0",
    "mode": "safe_validation",
    "banner": "DETECTION + SAFE VALIDATION ONLY — no destructive exploitation",
    "max_risk_class": "safe",
    "require_scope": True,
    "require_finding_link": True,
    "max_concurrent": 2,
    "max_per_run": 40,
    "request_timeout_sec": 15,
    "user_agent": "reconkit-prove/3.0.0",
    "allowed_techniques": [
        "xss_reflect",
        "ssti_math",
        "nuclei_recheck",
        "takeover_fingerprint",
        "ssrf_canary_review",
        "sqli_boolean",
        "jwt_inspect",
        "cors_origin",
        "graphql_typename",
        "redirect_canary",
        "idor_session_diff",
    ],
    "allow_sqli_boolean": False,
    "allow_oast_ssrf": True,
    "oast_base_url": "",
    "disallowed": [
        "sqlmap",
        "ghauri",
        "rce_shell",
        "credential_stuffing",
        "mass_scan",
        "data_exfil",
        "destructive",
    ],
}

_RISK_ORDER = {"safe": 0, "intrusive": 1, "destructive": 2}


def load_policy(path: Path | None = None) -> dict[str, Any]:
    p = path or REPO_POLICY
    data = deepcopy(DEFAULT_POLICY)
    if p.exists():
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                data.update(raw)
        except Exception:
            pass
    return data


def policy_summary(policy: dict[str, Any] | None = None) -> str:
    pol = policy or load_policy()
    lines = [
        f"mode:            {pol.get('mode')}",
        f"max_risk_class:  {pol.get('max_risk_class')}",
        f"max_per_run:     {pol.get('max_per_run')}",
        f"timeout:         {pol.get('request_timeout_sec')}s",
        f"techniques:      {', '.join(pol.get('allowed_techniques') or [])}",
        f"disallowed:      {', '.join(pol.get('disallowed') or [])}",
        f"banner:          {pol.get('banner')}",
        f"policy file:     {REPO_POLICY}",
    ]
    return "\n".join(lines)


def technique_allowed(technique: str, policy: dict[str, Any] | None = None) -> bool:
    pol = policy or load_policy()
    allowed = set(pol.get("allowed_techniques") or [])
    return technique in allowed


def risk_allowed(risk: str, policy: dict[str, Any] | None = None) -> bool:
    pol = policy or load_policy()
    max_r = str(pol.get("max_risk_class") or "safe").lower()
    return _RISK_ORDER.get(risk, 99) <= _RISK_ORDER.get(max_r, 0)
