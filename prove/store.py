"""Persist proof results under ~/.reconkit/output/<target>/proofs/."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import reconkit as rk

    OUTPUT_DIR = rk.OUTPUT_DIR
except Exception:  # pragma: no cover
    OUTPUT_DIR = Path.home() / ".reconkit" / "output"


def proofs_dir(target: str) -> Path:
    d = OUTPUT_DIR / target.replace("*", "_") / "proofs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def proofs_index_path(target: str) -> Path:
    return proofs_dir(target) / "proofs_index.json"


def save_proof(target: str, proof: dict[str, Any]) -> Path:
    d = proofs_dir(target)
    pid = proof.get("id") or "unknown"
    path = d / f"{pid}.json"
    path.write_text(json.dumps(proof, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _update_index(target, proof)
    return path


def _update_index(target: str, proof: dict[str, Any]) -> None:
    idx_path = proofs_index_path(target)
    data: dict[str, Any]
    if idx_path.exists():
        try:
            data = json.loads(idx_path.read_text(encoding="utf-8"))
        except Exception:
            data = {"target": target, "proofs": []}
    else:
        data = {"target": target, "proofs": []}
    proofs = [p for p in (data.get("proofs") or []) if p.get("id") != proof.get("id")]
    proofs.insert(0, {
        "id": proof.get("id"),
        "finding_id": proof.get("finding_id"),
        "technique": proof.get("technique"),
        "status": proof.get("status"),
        "title": proof.get("title"),
        "asset": (proof.get("asset") or "")[:200],
        "finished_at": proof.get("finished_at"),
    })
    data["proofs"] = proofs[:500]
    data["target"] = target
    idx_path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_proofs(target: str) -> list[dict[str, Any]]:
    d = proofs_dir(target)
    out: list[dict[str, Any]] = []
    for p in sorted(d.glob("*.json")):
        if p.name == "proofs_index.json":
            continue
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            continue
    return out


def list_all_proof_targets() -> list[str]:
    if not OUTPUT_DIR.exists():
        return []
    found = []
    for tdir in OUTPUT_DIR.iterdir():
        pdir = tdir / "proofs"
        if not tdir.is_dir() or not pdir.is_dir():
            continue
        has_json = any(p.name != "proofs_index.json" for p in pdir.glob("*.json"))
        if has_json:
            found.append(tdir.name)
    return sorted(found)


def load_all_proofs(target: str | None = None) -> list[dict[str, Any]]:
    """Load proofs for one target or every target under output/."""
    if target:
        return load_proofs(target)
    out: list[dict[str, Any]] = []
    for t in list_all_proof_targets():
        for p in load_proofs(t):
            if not p.get("target"):
                p = dict(p)
                p["target"] = t
            out.append(p)
    # newest first
    out.sort(key=lambda x: str(x.get("finished_at") or x.get("started_at") or ""), reverse=True)
    return out


def filter_proofs(
    proofs: list[dict[str, Any]],
    *,
    target: str | None = None,
    status: str | None = None,
    technique: str | None = None,
    q: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Filter proofs; return (page, stats)."""
    rows = list(proofs)
    if target:
        rows = [p for p in rows if p.get("target") == target]
    if status:
        rows = [p for p in rows if str(p.get("status") or "").lower() == status.lower()]
    if technique:
        rows = [p for p in rows if str(p.get("technique") or "") == technique]
    if q:
        ql = q.lower()
        rows = [
            p for p in rows
            if ql in json.dumps(p, ensure_ascii=False).lower()
        ]

    by_status: dict[str, int] = {}
    by_technique: dict[str, int] = {}
    by_target: dict[str, int] = {}
    for p in rows:
        s = str(p.get("status") or "unknown")
        t = str(p.get("technique") or "unknown")
        tg = str(p.get("target") or "?")
        by_status[s] = by_status.get(s, 0) + 1
        by_technique[t] = by_technique.get(t, 0) + 1
        by_target[tg] = by_target.get(tg, 0) + 1

    total = len(rows)
    if offset >= total and total > 0:
        offset = 0
    page = rows[offset : offset + max(1, limit)]
    stats = {
        "total": total,
        "offset": offset,
        "limit": limit,
        "by_status": by_status,
        "by_technique": by_technique,
        "by_target": by_target,
        "confirmed": by_status.get("confirmed", 0),
        "needs_manual": by_status.get("needs_manual", 0),
        "not_exploitable": by_status.get("not_exploitable", 0),
        "error": by_status.get("error", 0),
    }
    return page, stats


def proofs_overview(target: str | None = None) -> dict[str, Any]:
    all_p = load_all_proofs(target)
    _, stats = filter_proofs(all_p, target=target, limit=1, offset=0)
    return {
        "version": "2.1.0",
        "target": target or "",
        "proof_count": stats["total"],
        "by_status": stats["by_status"],
        "by_technique": stats["by_technique"],
        "by_target": stats["by_target"],
        "confirmed": stats["confirmed"],
        "needs_manual": stats["needs_manual"],
        "targets_with_proofs": list_all_proof_targets(),
    }
