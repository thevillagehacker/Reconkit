"""Two-session IDOR canary: GET same URL with cookie A vs B. Compare status/body. No dumps."""

from __future__ import annotations

import hashlib
from typing import Any

from hunter import session as sess


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    ha, hb = sess.headers(), sess.headers_b()
    if not ha or not hb:
        return {
            "status": "needs_manual",
            "evidence": "Set two sessions: /session set --cookie A  and  /session set --cookie-b B",
            "impact_note": "",
        }
    import re
    blob = str(item.get("asset") or "") + " " + str(item.get("evidence") or "")
    m = re.search(r"https?://[^\s\"'<>]+", blob)
    if not m:
        return {"status": "needs_manual", "evidence": "No URL.", "impact_note": ""}
    url = m.group(0).rstrip(").,;")
    ra = _get(url, ha, policy)
    rb = _get(url, hb, policy)
    ha_hash = hashlib.sha1((ra.get("body") or "").encode("utf-8", errors="replace")).hexdigest()[:12]
    hb_hash = hashlib.sha1((rb.get("body") or "").encode("utf-8", errors="replace")).hexdigest()[:12]
    ev = (
        f"url={url}\nA status={ra.get('status')} len={len(ra.get('body') or '')} hash={ha_hash}\n"
        f"B status={rb.get('status')} len={len(rb.get('body') or '')} hash={hb_hash}"
    )
    if ra.get("error") or rb.get("error"):
        return {"status": "error", "evidence": ev + f"\nerr A={ra.get('error')} B={rb.get('error')}", "impact_note": ""}
    same = ha_hash == hb_hash and ra.get("status") == rb.get("status")
    if not same and ra.get("status") == 200 and rb.get("status") in (200, 403, 401, 404):
        return {
            "status": "confirmed",
            "evidence": ev,
            "impact_note": (
                "Two-account responses differ. Confirm it is *your* objects only; "
                "do not pull other users' data in this toolkit."
            ),
        }
    if same:
        return {"status": "not_exploitable", "evidence": ev + "\nidentical responses", "impact_note": ""}
    return {"status": "needs_manual", "evidence": ev, "impact_note": "Difference is inconclusive."}


def _get(url: str, headers: dict[str, str], policy: dict[str, Any]) -> dict[str, Any]:
    import ssl
    import urllib.request
    h = {
        "User-Agent": str(policy.get("user_agent") or "reconkit-prove/3.0"),
        **headers,
    }
    req = urllib.request.Request(url, headers=h, method="GET")
    out = {"status": None, "body": "", "error": ""}
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=float(policy.get("request_timeout_sec") or 12), context=ctx) as resp:
            out["status"] = getattr(resp, "status", None) or resp.getcode()
            out["body"] = resp.read(80_000).decode("utf-8", errors="replace")
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out
