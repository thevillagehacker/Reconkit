"""Minimal HTTP helper for safe validators (stdlib only)."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def inject_query_marker(url: str, marker: str, prefer_params: list[str] | None = None) -> str:
    """
    Put marker into the first query parameter value (or append ?rk=marker).
    Does not invent path traversal or new hosts.
    """
    prefer = prefer_params or []
    try:
        parts = urlparse(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            return url
        q = list(parse_qsl(parts.query, keep_blank_values=True))
        if not q:
            q = [("rk_prove", marker)]
        else:
            replaced = False
            for i, (k, _v) in enumerate(q):
                if prefer and k.lower() not in [p.lower() for p in prefer]:
                    continue
                q[i] = (k, marker)
                replaced = True
                break
            if not replaced:
                # first param
                k, _ = q[0]
                q[0] = (k, marker)
        new_query = urlencode(q, doseq=True)
        return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, new_query, parts.fragment))
    except Exception:
        return url


def http_get(
    url: str,
    *,
    timeout: float = 15.0,
    user_agent: str = "reconkit-prove/3.0.0",
    max_bytes: int = 200_000,
) -> dict[str, Any]:
    """
    GET url; return status, body snippet, headers summary, error.
    TLS verification kept on; no redirects to other hosts beyond urllib default.
    """
    result: dict[str, Any] = {
        "url": url,
        "status": None,
        "body": "",
        "error": "",
        "final_url": url,
    }
    if not url.lower().startswith(("http://", "https://")):
        result["error"] = "not an http(s) URL"
        return result
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/json,*/*",
        },
        method="GET",
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status"] = getattr(resp, "status", None) or resp.getcode()
            result["final_url"] = resp.geturl()
            raw = resp.read(max_bytes)
            result["body"] = raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        try:
            result["body"] = e.read(max_bytes).decode("utf-8", errors="replace")
        except Exception:
            result["body"] = ""
        result["error"] = f"HTTPError {e.code}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result
