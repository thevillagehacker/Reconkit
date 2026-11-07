"""CORS: send Origin canary; confirm ACAO reflection. No credential theft."""

from __future__ import annotations

from typing import Any

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
    timeout = float(policy.get("request_timeout_sec") or 12)
    ua = str(policy.get("user_agent") or "reconkit-prove/3.0")
    r = http_get(
        url,
        timeout=timeout,
        user_agent=ua,
        extra_headers={"Origin": origin},
        merge_session=True,
    )
    if r.get("status") is None:
        return {"status": "error", "evidence": r.get("error") or "request failed", "impact_note": ""}
    hdrs = r.get("headers") or {}
    acao = hdrs.get("Access-Control-Allow-Origin") or hdrs.get("access-control-allow-origin") or ""
    acac = hdrs.get("Access-Control-Allow-Credentials") or hdrs.get("access-control-allow-credentials") or ""
    ev = f"url={url}\nOrigin={origin}\nACAO={acao}\nACAC={acac}\nHTTP {r.get('status')}"
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
