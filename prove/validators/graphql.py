"""GraphQL: POST {__typename} only. No introspection dump unless already in evidence."""

from __future__ import annotations

import json
from typing import Any

from prove.http_util import http_post


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    asset = (item.get("asset") or item.get("evidence") or "").strip()
    url = asset.split()[0] if asset.startswith("http") else ""
    if not url.startswith("http"):
        import re
        m = re.search(r"https?://\S+", asset)
        url = m.group(0).rstrip(",") if m else ""
    if not url:
        return {"status": "needs_manual", "evidence": "No GraphQL URL.", "impact_note": ""}
    body = json.dumps({"query": "{__typename}"}).encode()
    timeout = float(policy.get("request_timeout_sec") or 12)
    ua = str(policy.get("user_agent") or "reconkit-prove/3.0")
    r = http_post(
        url,
        body,
        timeout=timeout,
        user_agent=ua,
        extra_headers={"Content-Type": "application/json"},
        merge_session=True,
    )
    raw = r.get("body") or ""
    code = r.get("status")
    if code is None:
        return {"status": "error", "evidence": r.get("error") or "request failed", "impact_note": ""}
    ev = f"url={url}\nHTTP {code}\nbody={raw[:400]}"
    parsed: Any = None
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = None
    if isinstance(parsed, dict):
        data = parsed.get("data")
        if isinstance(data, dict) and "__typename" in data:
            return {
                "status": "confirmed",
                "evidence": ev,
                "impact_note": "Endpoint accepts GraphQL. Map schema privately; do not dump data here.",
            }
        errs = parsed.get("errors")
        if isinstance(errs, list) and errs:
            return {
                "status": "needs_manual",
                "evidence": ev,
                "impact_note": "GraphQL error payload — endpoint exists; check auth.",
            }
    if "__typename" in raw:
        return {
            "status": "confirmed",
            "evidence": ev,
            "impact_note": "Endpoint accepts GraphQL. Map schema privately; do not dump data here.",
        }
    return {"status": "not_exploitable", "evidence": ev, "impact_note": ""}
