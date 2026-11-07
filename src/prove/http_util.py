"""Minimal HTTP helper for safe validators (stdlib only)."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

_BLOCKED_NAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
}


def _blocked_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_unspecified
    )


def _host_related(origin: str, dest: str) -> bool:
    a = (origin or "").strip().lower().rstrip(".")
    b = (dest or "").strip().lower().rstrip(".")
    if not a or not b:
        return False
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def fetch_block_reason(url: str, scope_host: str | None = None) -> str:
    """Refuse non-HTTP, off-target, loopback, private, and link-local destinations.

    The scope check runs before DNS so an off-target name is rejected with no lookup.
    """
    try:
        parts = urlparse(url)
    except Exception:
        return "url could not be parsed"
    if parts.scheme not in ("http", "https"):
        return "not an http(s) URL"
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        return "missing host"
    if scope_host and not _host_related(scope_host, host):
        return "host is outside the target"
    if host in _BLOCKED_NAMES or host.endswith(".localhost"):
        return "local or metadata host"
    if _blocked_ip(host):
        return "blocked address"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return ""
    for info in infos:
        addr = info[4][0] if info and info[4] else ""
        if addr and _blocked_ip(addr):
            return "host resolves to a blocked address"
    return ""


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
    scope_host: str | None = None,
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
    origin = urlparse(url).hostname or ""
    bound = scope_host or origin
    headers = _merge_headers(user_agent, extra_headers, merge_session=merge_session)
    ctx = ssl.create_default_context()
    current = url
    hops = 0
    while hops < 4:
        reason = fetch_block_reason(current, scope_host=bound)
        if reason:
            result["error"] = reason
            result["final_url"] = current
            return result
        req = urllib.request.Request(current, headers=headers, method="GET")
        opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
        try:
            resp = opener.open(req, timeout=timeout)
            try:
                result["status"] = getattr(resp, "status", None) or resp.getcode()
                result["final_url"] = current
                result["headers"] = {str(k): str(v) for k, v in (resp.headers.items() if resp.headers else [])}
                raw = resp.read(max_bytes)
                result["body"] = raw.decode("utf-8", errors="replace")
                loc = (resp.headers.get("Location") if resp.headers else "") or ""
            finally:
                try:
                    resp.close()
                except Exception:
                    pass
        except urllib.error.HTTPError as e:
            result["status"] = e.code
            result["headers"] = {str(k): str(v) for k, v in (e.headers.items() if e.headers else [])}
            loc = (e.headers.get("Location") if e.headers else "") or ""
            try:
                result["body"] = e.read(max_bytes).decode("utf-8", errors="replace")
            except Exception:
                result["body"] = ""
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {e}"
            return result
        if not follow_redirects or result["status"] not in (301, 302, 303, 307, 308) or not loc:
            if loc:
                result["final_url"] = urljoin(current, loc)
            return result
        nxt = urljoin(current, loc)
        hop_reason = fetch_block_reason(nxt, scope_host=bound)
        if hop_reason:
            result["error"] = hop_reason
            result["final_url"] = nxt
            return result
        current = nxt
        hops += 1
        result["body"] = ""
    result["error"] = "too many redirects"
    result["final_url"] = current
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
    scope_host: str | None = None,
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
    bound = scope_host or (urlparse(url).hostname or "")
    reason = fetch_block_reason(url, scope_host=bound)
    if reason:
        result["error"] = reason
        return result
    headers = _merge_headers(user_agent, extra_headers, merge_session=merge_session)
    ctx = ssl.create_default_context()
    current = url
    payload: bytes | None = data
    for _hop in range(2):
        req = urllib.request.Request(current, data=payload, headers=headers, method="POST")
        opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
        loc = ""
        try:
            resp = opener.open(req, timeout=timeout)
            try:
                result["status"] = getattr(resp, "status", None) or resp.getcode()
                result["headers"] = {str(k): str(v) for k, v in (resp.headers.items() if resp.headers else [])}
                result["body"] = resp.read(max_bytes).decode("utf-8", errors="replace")
                loc = (resp.headers.get("Location") if resp.headers else "") or ""
            finally:
                resp.close()
        except urllib.error.HTTPError as e:
            result["status"] = e.code
            result["headers"] = {str(k): str(v) for k, v in (e.headers.items() if e.headers else [])}
            loc = (e.headers.get("Location") if e.headers else "") or ""
            try:
                result["body"] = e.read(max_bytes).decode("utf-8", errors="replace")
            except Exception:
                result["body"] = ""
        except Exception as e:
            result["error"] = f"{type(e).__name__}: {e}"
            return result
        if result["status"] not in (301, 302, 303, 307, 308) or not loc:
            return result
        nxt = urljoin(current, loc)
        hop_reason = fetch_block_reason(nxt, scope_host=bound)
        if hop_reason:
            result["error"] = hop_reason
            return result
        current = nxt
        if result["status"] in (301, 302, 303):
            payload = None
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
