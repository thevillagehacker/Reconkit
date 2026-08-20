"""Authenticated recon session (cookie / headers). Never commit this file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SESSION_FILE = Path.home() / ".reconkit" / "session.json"


def load() -> dict[str, Any]:
    if not SESSION_FILE.exists():
        return {}
    try:
        data = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save(data: dict[str, Any]) -> Path:
    SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        SESSION_FILE.chmod(0o600)
    except Exception:
        pass
    return SESSION_FILE


def clear() -> None:
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()


def headers() -> dict[str, str]:
    data = load()
    out: dict[str, str] = {}
    cookie = (data.get("cookie") or "").strip()
    if cookie:
        out["Cookie"] = cookie
    extra = data.get("headers") or {}
    if isinstance(extra, dict):
        for k, v in extra.items():
            if k and v:
                out[str(k)] = str(v)
    return out


def headers_b() -> dict[str, str]:
    """Second account for IDOR/authz diffs."""
    data = load()
    out: dict[str, str] = {}
    cookie = (data.get("cookie_b") or "").strip()
    if cookie:
        out["Cookie"] = cookie
    extra = data.get("headers_b") or {}
    if isinstance(extra, dict):
        for k, v in extra.items():
            if k and v:
                out[str(k)] = str(v)
    return out


def httpx_h_flags(account: str = "a") -> list[str]:
    h = headers() if account != "b" else headers_b()
    flags: list[str] = []
    for k, v in h.items():
        flags.extend(["-H", f"{k}: {v}"])
    return flags


def curl_flags(account: str = "a") -> list[str]:
    h = headers() if account != "b" else headers_b()
    flags: list[str] = []
    for k, v in h.items():
        flags.extend(["-H", f"{k}: {v}"])
    return flags


def summary() -> str:
    data = load()
    if not data:
        return "no session (unauthenticated recon)"
    bits = []
    if data.get("cookie"):
        bits.append("cookie-A")
    if data.get("cookie_b"):
        bits.append("cookie-B")
    if data.get("headers"):
        bits.append("headers-A:" + ",".join((data.get("headers") or {}).keys()))
    if data.get("headers_b"):
        bits.append("headers-B")
    return "session: " + ", ".join(bits) if bits else "empty session file"
