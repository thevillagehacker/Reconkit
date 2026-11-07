"""
SSRF validation (prove v2).

Default: classify recon evidence only (no internal/metadata hits).
Optional OAST: if policy.oast_base_url is set (e.g. https://YOUR.oast.live),
inject that callback into a URL parameter once and report the test URL for
the hunter to check their collaborator dashboard. Never probes 169.254.169.254.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse

from prove.http_util import http_get, inject_query_marker


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    ev = (item.get("evidence") or "") + "\n" + (item.get("title") or "")
    asset = item.get("asset") or ""
    low = (ev + asset).lower()

    signals = []
    for s in (
        "169.254.169.254",
        "metadata",
        "latest/meta-data",
        "ssrf",
        "collaborator",
        "interactsh",
        "oast",
    ):
        if s in low:
            signals.append(s)

    oast = (policy.get("oast_base_url") or "").strip().rstrip("/")
    url = _extract_url(asset) or _extract_url(ev)

    # Optional OAST probe (user-owned callback only)
    if oast and url and policy.get("allow_oast_ssrf", True):
        token = "rk" + hashlib.sha1((url + oast).encode()).hexdigest()[:12]
        # ensure oast is http(s)
        if not oast.lower().startswith(("http://", "https://")):
            oast = "https://" + oast
        # block obviously dangerous targets
        if any(x in oast.lower() for x in ("169.254.", "metadata", "localhost", "127.0.0.1")):
            return {
                "status": "skipped",
                "evidence": "oast_base_url looks unsafe/local — refused.",
                "impact_note": "",
            }
        callback = f"{oast}/{token}"
        test_url = inject_query_marker(url, callback)
        timeout = float(policy.get("request_timeout_sec") or 15)
        ua = str(policy.get("user_agent") or "reconkit-prove/2.2.0")
        resp = http_get(test_url, timeout=timeout, user_agent=ua)
        return {
            "status": "needs_manual",
            "evidence": (
                "OAST SSRF probe sent (check YOUR collaborator for hit).\n"
                f"callback={callback}\n"
                f"test_url={test_url}\n"
                f"HTTP status={resp.get('status')} err={resp.get('error') or 'ok'}\n"
                f"signals={signals or '(none from recon text)'}\n"
                "If the collaborator received a request, SSRF is likely confirmed."
            ),
            "impact_note": (
                "Out-of-band SSRF test fired against hunter-owned OAST only. "
                "Confirm hit in collaborator UI under program RoE."
            ),
            "meta": {
                "oast": True,
                "callback": callback,
                "test_url": test_url,
                "token": token,
                "signals": signals,
                "status_code": resp.get("status"),
            },
        }

    if signals:
        return {
            "status": "needs_manual",
            "evidence": (
                "SSRF-related recon signals present: "
                f"{signals}.\n"
                "Safe mode does not re-probe cloud metadata or internal IPs.\n"
                "To enable OAST: set oast_base_url in config/exploit_policy.json "
                "(your interactsh/collaborator URL), then re-run prove.\n"
                f"asset={asset}\nevidence={(item.get('evidence') or '')[:400]}"
            ),
            "impact_note": (
                "Possible SSRF candidate — use an authorized collaborator/OAST "
                "you control; do not scan third-party metadata from this toolkit."
            ),
            "meta": {"signals": signals, "oast": False},
        }

    return {
        "status": "skipped",
        "evidence": "No clear SSRF canary markers in finding; skipped.",
        "impact_note": "",
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
