"""
Per-target history snapshots and diffs (Tier A).

After each reindex, we store a lightweight snapshot of finding IDs + scores
under ~/.reconkit/history/<target>/. Diff compares latest two snapshots.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .store import BASE_DIR, ensure_index_dir

HISTORY_DIR = BASE_DIR / "history"
MAX_SNAPSHOTS = 30


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def history_dir(target: str) -> Path:
    safe = target.replace("*", "_").replace("/", "_")
    d = HISTORY_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_snapshot(target: str, findings: list[dict[str, Any]]) -> Path:
    """Write a snapshot for one target (subset of full index)."""
    d = history_dir(target)
    rows = [f for f in findings if f.get("target") == target]
    payload = {
        "target": target,
        "generated_at": _now(),
        "count": len(rows),
        "notable_count": sum(1 for r in rows if r.get("notable")),
        "ids": {r["id"]: {
            "score": r.get("score"),
            "severity": r.get("severity"),
            "module": r.get("module"),
            "ftype": r.get("ftype"),
            "title": r.get("title"),
            "asset": (r.get("asset") or "")[:300],
            "notable": r.get("notable"),
        } for r in rows if r.get("id")},
    }
    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f") + "Z.json"
    path = d / name
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _prune(d)
    # also write latest pointer
    (d / "latest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _prune(d: Path) -> None:
    snaps = sorted(
        [p for p in d.glob("*.json") if p.name != "latest.json"],
        key=lambda p: p.name,
    )
    while len(snaps) > MAX_SNAPSHOTS:
        snaps.pop(0).unlink(missing_ok=True)


def list_snapshots(target: str) -> list[Path]:
    d = history_dir(target)
    return sorted(
        [p for p in d.glob("*.json") if p.name != "latest.json"],
        key=lambda p: p.name,
    )


def load_snapshot(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def diff_target(target: str) -> dict[str, Any]:
    """Diff the two most recent snapshots for a target."""
    snaps = list_snapshots(target)
    if len(snaps) < 2:
        latest = snaps[-1] if snaps else None
        return {
            "target": target,
            "ok": False,
            "reason": "need at least two reindexes to diff",
            "snapshots": [p.name for p in snaps],
            "latest": latest.name if latest else None,
            "new": [],
            "gone": [],
            "changed_score": [],
        }
    older = load_snapshot(snaps[-2])
    newer = load_snapshot(snaps[-1])
    old_ids = older.get("ids") or {}
    new_ids = newer.get("ids") or {}
    added = []
    removed = []
    changed = []
    for i, meta in new_ids.items():
        if i not in old_ids:
            added.append({"id": i, **meta})
        elif old_ids[i].get("score") != meta.get("score") or old_ids[i].get("severity") != meta.get("severity"):
            changed.append({
                "id": i,
                "before": old_ids[i],
                "after": meta,
            })
    for i, meta in old_ids.items():
        if i not in new_ids:
            removed.append({"id": i, **meta})

    # sort new by score
    added.sort(key=lambda x: -int(x.get("score") or 0))
    return {
        "target": target,
        "ok": True,
        "older": snaps[-2].name,
        "newer": snaps[-1].name,
        "older_at": older.get("generated_at"),
        "newer_at": newer.get("generated_at"),
        "new_count": len(added),
        "gone_count": len(removed),
        "changed_count": len(changed),
        "new": added[:200],
        "gone": removed[:200],
        "changed_score": changed[:100],
    }


def snapshot_all_from_index(index: dict[str, Any]) -> list[Path]:
    """After reindex, snapshot each target present in the index."""
    findings = index.get("findings") or index.get("records") or []
    targets = set()
    for f in findings:
        t = f.get("target")
        if t:
            targets.add(t)
    # also empty targets from summaries
    for t in (index.get("targets") or {}):
        targets.add(t)
    paths = []
    for t in sorted(targets):
        paths.append(save_snapshot(t, findings))
    return paths
