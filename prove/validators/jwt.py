"""JWT inspection: decode header/payload only. No brute-force, no alg=none attack unless reflected."""

from __future__ import annotations

import base64
import json
import re
from typing import Any


def validate(item: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    blob = str(item.get("asset") or "") + " " + str(item.get("evidence") or "")
    m = re.search(r"eyJ[A-Za-z0-9_\-]*=*\.eyJ[A-Za-z0-9_\-]*=*\.[A-Za-z0-9_\-]*", blob)
    if not m:
        return {"status": "needs_manual", "evidence": "No JWT-shaped token on finding.", "impact_note": ""}
    token = m.group(0)
    parts = token.split(".")
    hdr = _b64json(parts[0]) if len(parts) > 0 else {}
    pay = _b64json(parts[1]) if len(parts) > 1 else {}
    alg = str((hdr or {}).get("alg") or "")
    notes = []
    if alg.lower() == "none":
        notes.append("alg=none (verify if accepted)")
    if alg.lower() in ("hs256", "hs384", "hs512"):
        notes.append("HMAC alg — do not brute in this toolkit")
    if not (hdr or pay):
        return {"status": "needs_manual", "evidence": "JWT did not decode.", "impact_note": ""}
    evidence = (
        f"alg={alg}\nheader={json.dumps(hdr)[:400]}\npayload_keys={list((pay or {}).keys())[:20]}\n"
        f"notes={notes or ['decode-only']}"
    )
    return {
        "status": "needs_manual",
        "evidence": evidence,
        "impact_note": (
            "Decode-only. alg=none in a token is a hint — do not treat as confirmed "
            "until a request shows the server accepted it."
        ),
        "meta": {"alg": alg, "header": hdr},
    }


def _b64json(seg: str) -> dict:
    s = seg + "=" * ((4 - len(seg) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(s.encode())
        obj = json.loads(raw.decode("utf-8", errors="replace"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}
