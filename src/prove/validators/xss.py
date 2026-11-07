"""Safe XSS reflection check with context classification (prove v2)."""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse

from prove.http_util import baseline_diff, http_get, inject_query_marker

_CONTEXT_HINTS = {
    "html_body": "Reflected in HTML text — often needs markup breakout.",
    "html_tag": "Appears inside/near a tag — attribute or event-handler risk.",
    "attr_quoted": "Inside quoted attribute — quote breakout may be required.",
    "javascript": "Inside script-like context — high impact if controllable.",
    "url_context": "Inside URL/href-like value — javascript: / open redirect paths.",
    "encoded": "Marker present but HTML-encoded — may still be usable in some sinks.",
    "unknown": "Reflected; classify sink manually.",
}


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    asset = (item.get("asset") or item.get("evidence") or "").strip()
    url = _extract_url(asset) or _extract_url(item.get("evidence") or "")
    if not url:
        return {
            "status": "needs_manual",
            "evidence": "No http(s) URL on finding — open asset manually.",
            "impact_note": "",
        }

    marker = "rkx" + hashlib.sha1(url.encode()).hexdigest()[:10]
    param = _reflected_param(asset) or _reflected_param(str(item.get("evidence") or ""))
    test_url = inject_query_marker(
        url,
        marker,
        prefer_params=[param] if param else None,
        replace_all=not param,
    )
    timeout = float(policy.get("request_timeout_sec") or 15)
    ua = str(policy.get("user_agent") or "reconkit-prove/2.2.0")
    base = http_get(url, timeout=timeout, user_agent=ua)
    resp = http_get(test_url, timeout=timeout, user_agent=ua)
    body = resp.get("body") or ""
    base_body = base.get("body") or ""
    if marker in base_body:
        return {
            "status": "false_positive",
            "evidence": (
                f"Baseline already contains marker {marker} — not injection.\nurl={url}"
            ),
            "impact_note": "",
            "meta": {"test_url": test_url, "baseline": True},
        }
    if resp.get("error") and resp.get("status") is None:
        return {
            "status": "error",
            "evidence": f"request failed: {resp.get('error')}\nurl={test_url}",
            "impact_note": "",
            "meta": {"test_url": test_url},
        }

    encoded_forms = [
        marker,
        marker.replace("<", "&lt;"),
        "".join(f"&#{ord(c)};" for c in marker[:6]) if False else "",
    ]
    # common encodings
    html_enc = (
        marker.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;").replace("'", "&#x27;")
    )

    reflected_raw = marker in body
    reflected_enc = html_enc in body and not reflected_raw
    reflected = reflected_raw or reflected_enc

    ctx = "unknown"
    next_step = ""
    if reflected:
        ctx = _classify_context(body, marker if reflected_raw else html_enc)
        if reflected_enc and ctx == "unknown":
            ctx = "encoded"
        next_step = _CONTEXT_HINTS.get(ctx, _CONTEXT_HINTS["unknown"])

    diff = baseline_diff(base, resp)
    if reflected:
        return {
            "status": "confirmed",
            "evidence": (
                f"Marker reflected (raw={reflected_raw}, encoded={reflected_enc}) "
                f"context={ctx} HTTP {resp.get('status')} "
                f"(baseline HTTP {base.get('status')}, len_diff={diff['len_diff']}).\n"
                f"url={test_url}\n"
                f"snippet={_snippet(body, marker if reflected_raw else html_enc)}\n"
                f"next={next_step}"
            ),
            "impact_note": (
                f"Input reflects in response (context: {ctx}). "
                f"{next_step} Confirm under program RoE — no auto weaponization."
            ),
            "meta": {
                "test_url": test_url,
                "context": ctx,
                "reflected_raw": reflected_raw,
                "reflected_encoded": reflected_enc,
                "status_code": resp.get("status"),
                "next_step": next_step,
            },
        }
    return {
        "status": "not_exploitable",
        "evidence": (
            f"Marker {marker} NOT found in response (HTTP {resp.get('status')}). "
            f"May be filtered, cached, or not a query-reflection sink.\nurl={test_url}"
        ),
        "impact_note": "",
        "meta": {"test_url": test_url, "status_code": resp.get("status"), "context": "none"},
    }


def _classify_context(body: str, marker: str) -> str:
    i = body.find(marker)
    if i < 0:
        return "unknown"
    window = body[max(0, i - 80) : i + len(marker) + 80]
    low = window.lower()

    # inside script block
    before = body[:i].lower()
    if before.rfind("<script") > before.rfind("</script"):
        return "javascript"
    if re.search(r"javascript\s*:", low) or "eval(" in low:
        return "javascript"
    if re.search(r"""(?:href|src|action|data)\s*=\s*['"][^'"]*$""" + re.escape(marker[:4]), window, re.I):
        return "url_context"
    if re.search(r"""=\s*['"][^'"]*""" + re.escape(marker), window):
        return "attr_quoted"
    if re.search(r"<[^>]*" + re.escape(marker), window):
        return "html_tag"
    if "&lt;" in marker or "&#" in marker:
        return "encoded"
    return "html_body"


def _reflected_param(text: str) -> str | None:
    """kxss/dalfox lines often end with `> param` or `param: name`."""
    blob = (text or "").strip()
    m = re.search(
        r"(?:[>\u003e]|param(?:eter)?\s*[:=])\s*([A-Za-z0-9_\-]{1,80})\s*$",
        blob,
        re.I,
    )
    return m.group(1) if m else None


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


def _snippet(body: str, marker: str, radius: int = 90) -> str:
    i = body.find(marker)
    if i < 0:
        return body[:160].replace("\n", " ")
    a = max(0, i - radius)
    b = min(len(body), i + len(marker) + radius)
    return body[a:b].replace("\n", " ")
