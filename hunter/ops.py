"""HAR import, evidence ZIP, notify, target wordlist, resume, scope-all."""

from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from hunter import session as sess


def _rk():
    import reconkit as rk
    return rk


def parse_har(path: Path, target: str) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    entries = (data.get("log") or {}).get("entries") or []
    urls: list[str] = []
    rk = _rk()
    for e in entries:
        u = ((e.get("request") or {}).get("url") or "").strip()
        if u.startswith("http") and rk.url_belongs_to_target(u, target):
            urls.append(u)
    # unique preserve order
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def import_har(har_path: str, target: str) -> dict[str, Any]:
    rk = _rk()
    rk.require_scope_or_exit(target)
    p = Path(har_path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(har_path)
    urls = parse_har(p, target)
    outdir = rk.OUTPUT_DIR / target.replace("*", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    dest = outdir / "urls.txt"
    existing = []
    if dest.exists():
        existing = [ln.strip() for ln in dest.read_text(errors="ignore").splitlines() if ln.strip()]
    merged = rk.filter_urls_to_target(existing + urls, target)
    dest.write_text("\n".join(merged) + ("\n" if merged else ""), encoding="utf-8")
    cookie = ""
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        for e in (data.get("log") or {}).get("entries") or []:
            headers = (e.get("request") or {}).get("headers") or []
            for h in headers:
                if str(h.get("name") or "").lower() == "cookie" and h.get("value"):
                    cookie = str(h.get("value"))
                    break
            if cookie:
                break
    except Exception:
        pass
    if cookie:
        s = sess.load()
        s["cookie"] = cookie
        sess.save(s)
    return {"urls": len(urls), "merged": len(merged), "cookie": bool(cookie), "outdir": str(outdir)}


def build_target_wordlist(target: str) -> Path:
    rk = _rk()
    outdir = rk.OUTPUT_DIR / target.replace("*", "_")
    words: set[str] = set()
    urls = outdir / "urls.txt"
    if urls.exists():
        for ln in urls.read_text(errors="ignore").splitlines():
            try:
                p = urlparse(ln.strip())
            except Exception:
                continue
            for part in (p.path or "").split("/"):
                part = part.strip()
                if 2 <= len(part) <= 40 and re_ok(part):
                    words.add(part)
    params = outdir / "param_names.txt"
    if params.exists():
        for ln in params.read_text(errors="ignore").splitlines():
            if ln.strip():
                words.add(ln.strip())
    dest = outdir / "wordlist_target.txt"
    dest.write_text("\n".join(sorted(words)) + ("\n" if words else ""), encoding="utf-8")
    return dest


def re_ok(s: str) -> bool:
    import re
    return bool(re.match(r"^[A-Za-z0-9_\-.]+$", s))


def evidence_zip(target: str, finding_id: str = "") -> Path:
    rk = _rk()
    outdir = rk.OUTPUT_DIR / target.replace("*", "_")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"evidence_{target}_{finding_id or 'pack'}_{stamp}.zip"
    dest = outdir / name
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for p in outdir.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() in {".zip"}:
                continue
            rel = str(p.relative_to(outdir)).replace("\\", "/")
            if finding_id and finding_id not in rel and p.suffix not in {".json", ".txt", ".md"}:
                # still include proofs matching id
                if "proofs" not in rel:
                    continue
            if p.stat().st_size > 4_000_000:
                continue
            z.write(p, rel)
    return dest


def notify_notable(target: str, n: int, extra: str = "") -> None:
    """Best-effort: projectdiscovery notify CLI if installed; else skip."""
    rk = _rk()
    bin_ = rk.which("notify")
    if not bin_ or n <= 0:
        return
    msg = f"reconkit {target}: {n} notable/C1+ findings. {extra}".strip()
    try:
        from run_control import run_interruptible
        env = os.environ.copy()
        env.update(rk.tool_env())
        run_interruptible(
            [bin_, "-silent"],
            env=env,
            capture=True,
            input_data=(msg + "\n").encode(),
        )
    except Exception:
        pass


def should_skip_module(name: str, outdir: Path, resume: bool) -> bool:
    if not resume:
        return False
    from agents.state import MODULE_OUTPUTS
    files = MODULE_OUTPUTS.get(name) or []
    if name == "nuclei":
        return any(outdir.glob("nuclei_*.txt"))
    for f in files:
        p = outdir / f
        if p.exists() and (p.is_dir() or p.stat().st_size > 0):
            return True
    return False


def scope_roots() -> list[str]:
    rk = _rk()
    roots = []
    for e in sorted(rk.load_scope()):
        e = e.strip()
        if not e or e.startswith("#"):
            continue
        if e.startswith("*."):
            e = e[2:]
        h = rk._normalize_host(e)
        if h and h not in roots:
            roots.append(h)
    return roots


def build_inbox(*, target: str | None = None, limit: int = 40) -> dict[str, Any]:
    """Prioritized C1+ hunter inbox (findings + suggested prove technique)."""
    findings: list[dict[str, Any]] = []
    try:
        from findings.indexer import query_store
        findings, _st = query_store(
            target=(target.strip() if target else None),
            notable=True,
            min_confidence="C1",
            limit=max(limit * 3, 60),
            offset=0,
        )
    except Exception:
        findings = []
    if not findings:
        try:
            from findings.store import load_index
            from findings.scoring import is_notable
            payload = load_index()
            findings = list(payload.get("findings") or [])
            if target:
                t = target.strip()
                findings = [f for f in findings if f.get("target") == t]
            findings = [f for f in findings if is_notable(f)]
        except Exception:
            findings = []

    try:
        from prove.queue import _map_technique
    except Exception:
        def _map_technique(_f):  # type: ignore
            return None

    rank = {"C4": 4, "C3": 3, "C2": 2, "C1": 1, "C0": 0}
    items: list[dict[str, Any]] = []
    for f in findings:
        conf = str(f.get("confidence") or "C1")[:2]
        tech = _map_technique(f)
        items.append({
            "id": f.get("id"),
            "target": f.get("target"),
            "title": f.get("title"),
            "asset": f.get("asset"),
            "module": f.get("module"),
            "severity": f.get("severity"),
            "score": f.get("score"),
            "confidence": f.get("confidence"),
            "technique": tech,
            "source_file": f.get("source_file"),
            "ftype": f.get("ftype"),
            "status": f.get("status"),
        })
    items.sort(
        key=lambda x: (
            -rank.get(str(x.get("confidence") or "C0")[:2], 0),
            -int(x.get("score") or 0),
        )
    )
    items = items[: max(1, min(limit, 200))]
    return {
        "count": len(items),
        "session": sess.summary(),
        "target": target or "",
        "items": items,
    }
