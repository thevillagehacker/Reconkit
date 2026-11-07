"""Two-session IDOR canary: GET same URL with cookie A vs B. Compare status/body. No dumps."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from hunter import session as sess
from prove.http_util import http_get


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    ha, hb = sess.headers(), sess.headers_b()
    if not ha or not hb:
        return {
            "status": "needs_manual",
            "evidence": "Set two sessions: /session set --cookie A  and  /session set --cookie-b B",
            "impact_note": "",
        }
    blob = str(item.get("asset") or "") + " " + str(item.get("evidence") or "")
    m = re.search(r"https?://[^\s\"'<>]+", blob)
    if not m:
        return {"status": "needs_manual", "evidence": "No URL.", "impact_note": ""}
    url = m.group(0).rstrip(").,;")
    timeout = float(policy.get("request_timeout_sec") or 12)
    ua = str(policy.get("user_agent") or "reconkit-prove/3.0")
    # Do not merge session A on top of B (Authorization would leak).
    ra = http_get(url, timeout=timeout, user_agent=ua, extra_headers=ha, merge_session=False)
    rb = http_get(url, timeout=timeout, user_agent=ua, extra_headers=hb, merge_session=False)
    ha_hash = hashlib.sha1((ra.get("body") or "").encode("utf-8", errors="replace")).hexdigest()[:12]
    hb_hash = hashlib.sha1((rb.get("body") or "").encode("utf-8", errors="replace")).hexdigest()[:12]
    ev = (
        f"url={url}\nA status={ra.get('status')} len={len(ra.get('body') or '')} hash={ha_hash}\n"
        f"B status={rb.get('status')} len={len(rb.get('body') or '')} hash={hb_hash}"
    )
    if ra.get("status") is None or rb.get("status") is None:
        return {
            "status": "error",
            "evidence": ev + f"\nerr A={ra.get('error')} B={rb.get('error')}",
            "impact_note": "",
        }
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
