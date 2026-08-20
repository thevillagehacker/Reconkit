"""Safe nuclei recheck: re-run a single template against one URL (not disk tautology)."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from prove.http_util import http_get

try:
    import reconkit as rk

    OUTPUT_DIR = rk.OUTPUT_DIR
except Exception:
    OUTPUT_DIR = Path.home() / ".reconkit" / "output"


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    target = item.get("target") or ""
    asset = (item.get("asset") or "").strip()
    title = item.get("title") or ""
    evidence = item.get("evidence") or ""
    outdir = OUTPUT_DIR / str(target).replace("*", "_")

    url = _extract_url(asset) or _extract_url(evidence)
    template_id = _template_id(evidence, title, asset)

    nuclei = shutil.which("nuclei")
    if nuclei and url and template_id:
        timeout = float(policy.get("request_timeout_sec") or 25)
        try:
            r = subprocess.run(
                [
                    nuclei, "-u", url, "-id", template_id,
                    "-silent", "-nc", "-timeout", "10",
                ],
                capture_output=True,
                text=True,
                timeout=max(15.0, timeout + 5),
            )
        except Exception as e:
            return {
                "status": "error",
                "evidence": f"nuclei recheck failed: {type(e).__name__}: {e}",
                "impact_note": "",
                "meta": {"template_id": template_id, "url": url},
            }
        out = (r.stdout or "") + (r.stderr or "")
        hit = bool((r.stdout or "").strip())
        if hit:
            return {
                "status": "confirmed",
                "evidence": (
                    f"Re-ran nuclei -id {template_id} against {url} (exit={r.returncode}).\n"
                    f"hit:\n{(r.stdout or '')[:500]}"
                ),
                "impact_note": (
                    "Single-template recheck still matches. Confirm impact under RoE; "
                    "info/low templates are often not bounty-relevant."
                ),
                "meta": {
                    "template_id": template_id,
                    "url": url,
                    "rerun": True,
                    "exit": r.returncode,
                },
            }
        return {
            "status": "false_positive",
            "evidence": (
                f"Re-ran nuclei -id {template_id} against {url} — no match "
                f"(exit={r.returncode}).\nstderr={(r.stderr or '')[:240]}"
            ),
            "impact_note": "",
            "meta": {"template_id": template_id, "url": url, "rerun": True},
        }

    # Fallback: artifact + optional GET (cannot confirm from disk alone)
    still = _search_nuclei_files(outdir, asset, title, evidence)
    http_note = ""
    if url:
        timeout = float(policy.get("request_timeout_sec") or 15)
        ua = str(policy.get("user_agent") or "reconkit-prove/3.0.0")
        resp = http_get(url, timeout=timeout, user_agent=ua)
        http_note = f"\nHTTP GET {url} → status={resp.get('status')} err={resp.get('error') or 'ok'}"

    if still:
        return {
            "status": "needs_manual",
            "evidence": (
                "nuclei binary or template id unavailable for a live recheck. "
                "Artifact still on disk (not a confirmation):\n"
                f"match: {still[:400]}"
                f"{http_note}"
            ),
            "impact_note": "Re-run nuclei on this URL/template before reporting.",
            "meta": {"artifact_match": True, "template_id": template_id, "url": url},
        }

    if url:
        return {
            "status": "needs_manual",
            "evidence": (
                "Could not re-run nuclei and no matching artifact line.\n"
                f"{http_note}\noriginal: {(evidence or title)[:300]}"
            ),
            "impact_note": "",
            "meta": {"artifact_match": False, "template_id": template_id},
        }

    return {
        "status": "false_positive",
        "evidence": "No URL, no template id, and no matching nuclei artifact.",
        "impact_note": "",
    }


def _template_id(evidence: str, title: str, asset: str) -> str:
    blob = f"{evidence}\n{title}\n{asset}"
    # Typical: [cve-2021-xxxx] [http] [high] url
    m = re.search(r"\[([a-zA-Z0-9][a-zA-Z0-9._-]{2,80})\]", blob)
    if m:
        tid = m.group(1)
        if tid.lower() not in {"info", "low", "medium", "high", "critical", "http", "dns", "tcp", "ssl"}:
            return tid
    return ""


def _search_nuclei_files(outdir: Path, asset: str, title: str, evidence: str) -> str:
    if not outdir.exists():
        return ""
    needles = [x for x in (asset, title) if x and len(x) > 4]
    keys = [n[:80] for n in needles]
    m = re.search(r"\[([a-zA-Z0-9_-]+)\]", evidence or "")
    if m:
        keys.append(m.group(1))

    for path in list(outdir.glob("nuclei*")) + list(outdir.glob("**/*nuclei*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for k in keys:
            if k and k in text:
                for line in text.splitlines():
                    if k in line:
                        return f"{path.name}: {line[:300]}"
        if path.suffix == ".json" or "json" in path.name:
            for line in text.splitlines()[:5000]:
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                blob = json.dumps(obj)
                for k in keys:
                    if k and k in blob:
                        return f"{path.name}: {blob[:300]}"
    return ""


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
