"""Safe nuclei recheck: re-read local nuclei output; optional single HTTP GET on asset."""

from __future__ import annotations

import json
import re
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

    # Find still-present line in nuclei outputs
    still = _search_nuclei_files(outdir, asset, title, evidence)
    http_note = ""
    url = _extract_url(asset) or _extract_url(evidence)
    if url:
        timeout = float(policy.get("request_timeout_sec") or 15)
        ua = str(policy.get("user_agent") or "reconkit-prove/2.1.0")
        resp = http_get(url, timeout=timeout, user_agent=ua)
        http_note = f"\nHTTP GET {url} → status={resp.get('status')} err={resp.get('error') or 'ok'}"

    if still:
        return {
            "status": "confirmed",
            "evidence": (
                "Nuclei finding still present in local scan artifacts.\n"
                f"match: {still[:400]}"
                f"{http_note}"
            ),
            "impact_note": (
                "Template match remains in recon output — re-validate with latest nuclei "
                "manually if reporting; this step does not re-run full nuclei."
            ),
            "meta": {"artifact_match": True},
        }

    if url and http_note:
        return {
            "status": "needs_manual",
            "evidence": (
                "Could not re-find exact nuclei line in artifacts; asset still reachable?\n"
                f"{http_note}\noriginal: {(evidence or title)[:300]}"
            ),
            "impact_note": "",
            "meta": {"artifact_match": False},
        }

    return {
        "status": "false_positive",
        "evidence": "No matching nuclei artifact and no URL to probe. May have been cleaned or path moved.",
        "impact_note": "",
    }


def _search_nuclei_files(outdir: Path, asset: str, title: str, evidence: str) -> str:
    if not outdir.exists():
        return ""
    needles = [x for x in (asset, title) if x and len(x) > 4]
    keys = []
    for n in needles:
        keys.append(n[:80])
    # template id in evidence
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
        # jsonl nuclei
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
