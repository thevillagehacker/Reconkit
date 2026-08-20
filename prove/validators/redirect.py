"""Open redirect: inject canary URL, check Location / body. Hunter-owned OAST or .invalid."""

from __future__ import annotations

import re
from typing import Any

from prove.http_util import http_get, inject_query_marker


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
    test = inject_query_marker(url, marker)
    # follow_redirects is urllib default — we need Location of first hop.
    import ssl
    import urllib.error
    import urllib.request
    req = urllib.request.Request(
        test,
        headers={"User-Agent": str(policy.get("user_agent") or "reconkit-prove/3.0")},
        method="GET",
    )
    loc = ""
    code = None
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler)
    # Don't follow: HTTPError on 3xx isn't raised if handler follows. Use urlopen without follow:
    class NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        ctx = ssl.create_default_context()
        opener = urllib.request.build_opener(NoRedir, urllib.request.HTTPSHandler(context=ctx))
        resp = opener.open(req, timeout=float(policy.get("request_timeout_sec") or 12))
        code = getattr(resp, "status", None) or resp.getcode()
        loc = resp.headers.get("Location") or resp.geturl() or ""
        body = resp.read(1500).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        code = e.code
        loc = e.headers.get("Location") or ""
        body = ""
        try:
            body = e.read(1500).decode("utf-8", errors="replace")
        except Exception:
            pass
    except Exception as e:
        return {"status": "error", "evidence": str(e), "impact_note": ""}
    ev = f"test={test}\nHTTP {code}\nLocation={loc}\n"
    if marker.rstrip("/") in (loc or "") or "rk-redirect" in (loc or "") or "rk-redirect" in body:
        return {
            "status": "confirmed",
            "evidence": ev,
            "impact_note": "Redirect/canary bounce observed. Confirm unauthenticated impact.",
        }
    return {"status": "not_exploitable", "evidence": ev, "impact_note": ""}
