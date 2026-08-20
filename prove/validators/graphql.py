"""GraphQL: POST {__typename} only. No introspection dump unless already in evidence."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any


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
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json",
                 "User-Agent": str(policy.get("user_agent") or "reconkit-prove/3.0")},
        method="POST",
    )
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=float(policy.get("request_timeout_sec") or 12), context=ctx) as resp:
            raw = resp.read(4000).decode("utf-8", errors="replace")
            code = getattr(resp, "status", None) or resp.getcode()
    except urllib.error.HTTPError as e:
        raw = e.read(4000).decode("utf-8", errors="replace") if e.fp else ""
        code = e.code
    except Exception as e:
        return {"status": "error", "evidence": str(e), "impact_note": ""}
    ev = f"url={url}\nHTTP {code}\nbody={raw[:400]}"
    if "__typename" in raw or '"data"' in raw:
        return {
            "status": "confirmed",
            "evidence": ev,
            "impact_note": "Endpoint accepts GraphQL. Map schema privately; do not dump data here.",
        }
    if "error" in raw.lower() and "graphql" in raw.lower():
        return {"status": "needs_manual", "evidence": ev, "impact_note": "GraphQL-like errors."}
    return {"status": "not_exploitable", "evidence": ev, "impact_note": ""}
