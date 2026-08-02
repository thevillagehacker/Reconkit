"""Safe takeover fingerprint: DNS CNAME + HTTP body fingerprints only (no registrar actions)."""

from __future__ import annotations

import re
import socket
import subprocess
from typing import Any
from urllib.parse import urlparse

from prove.http_util import http_get

# Common dangling fingerprints (read-only body/DNS hints)
_FINGERPRINTS = [
    (r"NoSuchBucket", "aws_s3"),
    (r"The specified bucket does not exist", "aws_s3"),
    (r"No Such Account", "github_pages_like"),
    (r"There's nothing here", "ghost_like"),
    (r"repository not found", "github"),
    (r"Heroku \| No such app", "heroku"),
    (r"Fastly error: unknown domain", "fastly"),
    (r"The feed has not been found", "feedpress"),
    (r"Sorry, this shop is currently unavailable", "shopify"),
    (r"Do you want to register", "wordpress_com"),
]


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    asset = (item.get("asset") or "").strip()
    host = _host_from_asset(asset) or _host_from_asset(item.get("evidence") or "")
    if not host:
        return {
            "status": "needs_manual",
            "evidence": "No hostname extracted for takeover check.",
            "impact_note": "",
        }

    cname = _lookup_cname(host)
    a_recs = _lookup_a(host)
    timeout = float(policy.get("request_timeout_sec") or 15)
    ua = str(policy.get("user_agent") or "reconkit-prove/2.1.0")
    bodies = []
    for scheme in ("https", "http"):
        resp = http_get(f"{scheme}://{host}/", timeout=timeout, user_agent=ua)
        if resp.get("body"):
            bodies.append(resp.get("body") or "")
        if resp.get("status"):
            break

    body = "\n".join(bodies)
    hits = []
    for pat, name in _FINGERPRINTS:
        if re.search(pat, body, re.I):
            hits.append(name)

    evidence = (
        f"host={host}\n"
        f"CNAME={cname or '(none)'}\n"
        f"A={a_recs or '(none)'}\n"
        f"fingerprints={hits or '(none)'}\n"
        f"body_snippet={(body[:240] or '').replace(chr(10), ' ')}"
    )

    if hits and cname:
        return {
            "status": "confirmed",
            "evidence": evidence,
            "impact_note": (
                "Dangling CNAME + provider fingerprint — possible subdomain takeover. "
                "Do NOT auto-claim; follow program rules and provider process manually."
            ),
            "meta": {"cname": cname, "fingerprints": hits},
        }
    if hits or cname:
        return {
            "status": "needs_manual",
            "evidence": evidence,
            "impact_note": "Partial takeover signals — manual DNS/provider review required.",
            "meta": {"cname": cname, "fingerprints": hits},
        }
    return {
        "status": "not_exploitable",
        "evidence": evidence,
        "impact_note": "",
        "meta": {"cname": cname, "fingerprints": hits},
    }


def _host_from_asset(text: str) -> str | None:
    text = (text or "").strip()
    if not text:
        return None
    if "://" in text:
        try:
            p = urlparse(text)
            if p.hostname:
                return p.hostname.lower()
        except Exception:
            pass
    # bare host or host CNAME line
    m = re.search(r"([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})", text)
    if m:
        return m.group(1).lower().rstrip(".")
    return None


def _lookup_cname(host: str) -> str:
    # try dig/nslookup/socket
    for cmd in (
        ["dig", "+short", "CNAME", host],
        ["nslookup", "-type=CNAME", host],
    ):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            out = (r.stdout or "") + (r.stderr or "")
            if r.returncode == 0 or out:
                for line in out.splitlines():
                    line = line.strip()
                    if not line or line.startswith(";") or "canonical" in line.lower():
                        # nslookup forms
                        if "canonical name" in line.lower():
                            parts = line.split("=")
                            if len(parts) > 1:
                                return parts[-1].strip().rstrip(".")
                        continue
                    if re.match(r"^[a-zA-Z0-9._-]+\.$", line) or re.match(r"^[a-zA-Z0-9._-]+$", line):
                        if " " not in line and "nslookup" not in line.lower():
                            return line.rstrip(".")
        except Exception:
            continue
    try:
        # python may not expose CNAME easily without dnspython
        socket.getaddrinfo(host, None)
    except Exception:
        pass
    return ""


def _lookup_a(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        return ips[:8]
    except Exception:
        return []
