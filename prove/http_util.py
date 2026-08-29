"""Minimal HTTP helper for safe validators (stdlib only)."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def inject_query_marker(
    url: str,
    marker: str,
    prefer_params: list[str] | None = None,
    *,
    replace_all: bool = False,
) -> str:
    """
    Put marker into query parameter value(s) (or append ?rk_prove=marker).
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
        elif replace_all and not prefer:
            q = [(k, marker) for k, _v in q]
        else:
            replaced = False
            for i, (k, _v) in enumerate(q):
                if prefer and k.lower() not in [p.lower() for p in prefer]:
                    continue
                q[i] = (k, marker)
                replaced = True
                if not prefer:
                    break
                # preferred name: replace every matching key
            if not replaced:
                k, _ = q[0]
                q[0] = (k, marker)
        new_query = urlencode(q, doseq=True)
        return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, new_query, parts.fragment))
    except Exception:
        return url


def _merge_headers(
    user_agent: str,
    extra_headers: dict[str, str] | None,
    *,
    merge_session: bool,
) -> dict[str, str]:
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/json,*/*",
    }
    if merge_session:
        try:
            from hunter.session import headers as sess_headers
            for k, v in (sess_headers() or {}).items():
                if k and v:
                    headers[str(k)] = str(v)
        except Exception:
            pass
    if extra_headers:
        for k, v in extra_headers.items():
            if k and v is not None:
                headers[str(k)] = str(v)
    return headers


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ARG002
        return None


def http_get(
    url: str,
    *,
    timeout: float = 15.0,
    user_agent: str = "reconkit-prove/3.0.0",
    max_bytes: int = 200_000,
    extra_headers: dict[str, str] | None = None,
    merge_session: bool = True,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    """
    GET url; return status, body snippet, response headers, error.
    TLS verification stays on. HTTP 4xx/5xx set status (not error).
    merge_session=False skips hunter cookie A (use for IDOR account B).
    """
    result: dict[str, Any] = {
        "url": url,
        "status": None,
        "body": "",
        "error": "",
        "final_url": url,
        "headers": {},
    }
    if not url.lower().startswith(("http://", "https://")):
        result["error"] = "not an http(s) URL"
        return result
    headers = _merge_headers(user_agent, extra_headers, merge_session=merge_session)
    req = urllib.request.Request(url, headers=headers, method="GET")
    ctx = ssl.create_default_context()
    handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow_redirects:
        handlers.insert(0, _NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    try:
        resp = opener.open(req, timeout=timeout)
        try:
            result["status"] = getattr(resp, "status", None) or resp.getcode()
            result["final_url"] = resp.geturl()
            result["headers"] = {str(k): str(v) for k, v in (resp.headers.items() if resp.headers else [])}
            raw = resp.read(max_bytes)
            result["body"] = raw.decode("utf-8", errors="replace")
        finally:
            try:
                resp.close()
            except Exception:
                pass
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["headers"] = {str(k): str(v) for k, v in (e.headers.items() if e.headers else [])}
        loc = (e.headers.get("Location") if e.headers else "") or ""
        if loc:
            result["final_url"] = loc
        try:
            result["body"] = e.read(max_bytes).decode("utf-8", errors="replace")
        except Exception:
            result["body"] = ""
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result


def http_post(
    url: str,
    data: bytes,
    *,
    timeout: float = 15.0,
    user_agent: str = "reconkit-prove/3.0.0",
    max_bytes: int = 200_000,
    extra_headers: dict[str, str] | None = None,
    merge_session: bool = True,
) -> dict[str, Any]:
    """POST bytes; HTTP 4xx still returns status/body (not error)."""
    result: dict[str, Any] = {
        "url": url,
        "status": None,
        "body": "",
        "error": "",
        "headers": {},
    }
    if not url.lower().startswith(("http://", "https://")):
        result["error"] = "not an http(s) URL"
        return result
    headers = _merge_headers(user_agent, extra_headers, merge_session=merge_session)
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["status"] = getattr(resp, "status", None) or resp.getcode()
            result["headers"] = {str(k): str(v) for k, v in (resp.headers.items() if resp.headers else [])}
            result["body"] = resp.read(max_bytes).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["headers"] = {str(k): str(v) for k, v in (e.headers.items() if e.headers else [])}
        try:
            result["body"] = e.read(max_bytes).decode("utf-8", errors="replace")
        except Exception:
            result["body"] = ""
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result


def body_hash(body: str) -> str:
    import hashlib
    return hashlib.sha1((body or "").encode("utf-8", errors="replace")).hexdigest()[:16]


def baseline_diff(original: dict[str, Any], probed: dict[str, Any]) -> dict[str, Any]:
    """Compare a baseline GET vs an injected GET."""
    ob = original.get("body") or ""
    pb = probed.get("body") or ""
    return {
        "status_orig": original.get("status"),
        "status_probe": probed.get("status"),
        "len_orig": len(ob),
        "len_probe": len(pb),
        "len_diff": abs(len(ob) - len(pb)),
        "status_diff": original.get("status") != probed.get("status"),
        "hash_orig": body_hash(ob),
        "hash_probe": body_hash(pb),
        "hash_diff": body_hash(ob) != body_hash(pb),
    }
