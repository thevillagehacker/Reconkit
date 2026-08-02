"""Safe SSTI canary: {{7*7}} → look for 49 once. No RCE payloads."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from prove.http_util import http_get, inject_query_marker

CANARY = "{{7*7}}"
EXPECTED = "49"


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    asset = (item.get("asset") or "") + " " + (item.get("evidence") or "")
    url = _extract_url(asset)
    if not url:
        # evidence-only confirmation from recon already saying 49
        ev = item.get("evidence") or ""
        if EXPECTED in ev and ("ssti" in ev.lower() or CANARY in ev):
            return {
                "status": "confirmed",
                "evidence": "Recon evidence already contains SSTI canary hit (49). Manual review recommended.\n" + ev[:500],
                "impact_note": "Template injection canary observed during recon — validate impact carefully under RoE.",
            }
        return {
            "status": "needs_manual",
            "evidence": "No URL to re-test; review recon ssti_candidates.txt manually.",
            "impact_note": "",
        }

    test_url = inject_query_marker(url, CANARY)
    timeout = float(policy.get("request_timeout_sec") or 15)
    ua = str(policy.get("user_agent") or "reconkit-prove/2.1.0")
    resp = http_get(test_url, timeout=timeout, user_agent=ua)
    body = resp.get("body") or ""
    if resp.get("error") and resp.get("status") is None:
        return {
            "status": "error",
            "evidence": f"request failed: {resp.get('error')}\nurl={test_url}",
            "impact_note": "",
        }

    # Prefer seeing 49 near template-ish context; simple presence is enough for canary
    if EXPECTED in body and CANARY not in body:
        return {
            "status": "confirmed",
            "evidence": (
                f"Injected {CANARY}; response contains '{EXPECTED}' and not the raw canary "
                f"(HTTP {resp.get('status')}).\nurl={test_url}\nsnippet={body[:200].replace(chr(10), ' ')}"
            ),
            "impact_note": (
                "SSTI math canary succeeded — potential template injection. "
                "Do not escalate to RCE payloads in this toolkit."
            ),
            "meta": {"test_url": test_url, "status_code": resp.get("status")},
        }
    if EXPECTED in body and CANARY in body:
        return {
            "status": "needs_manual",
            "evidence": f"Both canary and 49 present; ambiguous.\nurl={test_url}",
            "impact_note": "",
            "meta": {"test_url": test_url},
        }
    return {
        "status": "not_exploitable",
        "evidence": f"Canary not evaluated (no clear '{EXPECTED}'). HTTP {resp.get('status')}\nurl={test_url}",
        "impact_note": "",
        "meta": {"test_url": test_url, "status_code": resp.get("status")},
    }


def _extract_url(text: str) -> str | None:
    m = re.search(r"https?://[^\s\"'<>]+", text or "")
    if not m:
        return None
    url = m.group(0).rstrip(").,;]")
    try:
        p = urlparse(url)
        if p.scheme in ("http", "https") and p.netloc:
            return url
    except Exception:
        return None
    return None
