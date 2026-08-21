"""Open redirect: inject canary URL, check Location / body. Hunter-owned OAST or .invalid."""

from __future__ import annotations

import re
from typing import Any

from prove.http_util import http_get, inject_query_marker

_REDIRECT_PARAMS = [
    "next", "url", "redirect", "redirect_uri", "return", "returnUrl", "return_url",
    "dest", "destination", "continue", "rurl", "target", "goto", "redir",
]


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    blob = str(item.get("asset") or "") + " " + str(item.get("evidence") or "")
    m = re.search(r"https?://[^\s\"'<>]+", blob)
    if not m:
        return {"status": "needs_manual", "evidence": "No URL.", "impact_note": ""}
    url = m.group(0).rstrip(").,;")
    bounce = (policy.get("oast_base_url") or "").strip().rstrip("/")
    if bounce.startswith("http"):
        marker = bounce + "/rk-redirect"
    else:
        marker = "https://rk-redirect-check.invalid/"
    test = inject_query_marker(url, marker, prefer_params=_REDIRECT_PARAMS)
    timeout = float(policy.get("request_timeout_sec") or 12)
    ua = str(policy.get("user_agent") or "reconkit-prove/3.0")
    r = http_get(
        test,
        timeout=timeout,
        user_agent=ua,
        merge_session=True,
        follow_redirects=False,
    )
    if r.get("status") is None and r.get("error"):
        return {"status": "error", "evidence": r.get("error") or "", "impact_note": ""}
    loc = (
        (r.get("headers") or {}).get("Location")
        or (r.get("headers") or {}).get("location")
        or r.get("final_url")
        or ""
    )
    body = r.get("body") or ""
    ev = f"test={test}\nHTTP {r.get('status')}\nLocation={loc}\n"
    if marker.rstrip("/") in (loc or "") or "rk-redirect" in (loc or "") or "rk-redirect" in body:
        return {
            "status": "confirmed",
            "evidence": ev,
            "impact_note": "Redirect/canary bounce observed. Confirm unauthenticated impact.",
        }
    return {"status": "not_exploitable", "evidence": ev, "impact_note": ""}
