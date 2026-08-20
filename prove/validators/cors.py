"""CORS: send Origin canary; confirm ACAO reflection. No credential theft."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from prove.http_util import http_get


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    asset = (item.get("asset") or item.get("evidence") or "").strip()
    url = asset.split()[0] if asset.startswith("http") else ""
    if not url.startswith("http"):
        import re
        m = re.search(r"https?://\S+", asset)
        url = m.group(0) if m else ""
    if not url:
        return {"status": "needs_manual", "evidence": "No URL for CORS probe.", "impact_note": ""}
    origin = "https://rk-cors-check.invalid"
    # stdlib GET with Origin — http_get doesn't set Origin; use urllib
    import ssl
    import urllib.request
    req = urllib.request.Request(
        url,
        headers={
            "Origin": origin,
            "User-Agent": str(policy.get("user_agent") or "reconkit-prove/3.0"),
        },
        method="GET",
    )
    acao = acac = ""
    status = None
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=float(policy.get("request_timeout_sec") or 12), context=ctx) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            acao = resp.headers.get("Access-Control-Allow-Origin") or ""
            acac = resp.headers.get("Access-Control-Allow-Credentials") or ""
    except Exception as e:
        return {"status": "error", "evidence": str(e), "impact_note": ""}
    ev = f"url={url}\nOrigin={origin}\nACAO={acao}\nACAC={acac}\nHTTP {status}"
    if origin in acao and "true" in acac.lower():
        return {
            "status": "confirmed",
            "evidence": ev,
            "impact_note": "Reflected origin + credentials. Confirm impact under RoE.",
        }
    if origin in acao or acao.strip() == "*":
        return {
            "status": "needs_manual",
            "evidence": ev,
            "impact_note": "ACAO interesting; credentials may be off — usually not bounty alone.",
        }
    return {"status": "not_exploitable", "evidence": ev, "impact_note": ""}
