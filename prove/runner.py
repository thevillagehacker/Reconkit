"""Run safe validators against a queue of findings."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Callable

from .models import ProofAttempt
from .policy import load_policy, risk_allowed, technique_allowed
from .store import load_proofs, save_proof
from .validators import get_validator, list_techniques


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _proof_id(finding_id: str, technique: str) -> str:
    raw = f"{finding_id}|{technique}|{_now()[:13]}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def run_one(
    item: dict[str, Any],
    *,
    policy: dict[str, Any] | None = None,
    scope_check: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    """
    Validate one queue item. Returns proof dict.
    scope_check(target) -> bool if provided.
    """
    pol = policy or load_policy()
    target = str(item.get("target") or "")
    technique = str(item.get("technique") or "")
    finding_id = str(item.get("finding_id") or "")
    risk = str(item.get("risk_class") or "safe")

    proof = ProofAttempt(
        id=_proof_id(finding_id or item.get("asset") or "x", technique or "none"),
        finding_id=finding_id,
        target=target,
        technique=technique,
        risk_class=risk if risk in ("safe", "intrusive", "destructive") else "safe",
        status="running",
        title=str(item.get("title") or ""),
        asset=str(item.get("asset") or ""),
        module=str(item.get("module") or ""),
        source_file=str(item.get("source_file") or ""),
        started_at=_now(),
        meta={},
    )

    if pol.get("require_scope", True) and scope_check is not None:
        if not target or not scope_check(target):
            proof.status = "error"
            proof.evidence = f"Target not in scope: {target}"
            proof.finished_at = _now()
            d = proof.to_dict()
            if target:
                save_proof(target, d)
            return d

    if technique in ("manual", ""):
        proof.status = "needs_manual"
        proof.evidence = item.get("reason") or "No safe auto-validator for this finding."
        proof.finished_at = _now()
        d = proof.to_dict()
        save_proof(target, d)
        return d

    if not technique_allowed(technique, pol):
        proof.status = "skipped"
        proof.evidence = f"Technique '{technique}' not allowed by policy."
        proof.finished_at = _now()
        d = proof.to_dict()
        save_proof(target, d)
        return d

    if not risk_allowed(proof.risk_class, pol):
        proof.status = "skipped"
        proof.evidence = f"Risk class '{proof.risk_class}' exceeds policy max_risk_class."
        proof.finished_at = _now()
        d = proof.to_dict()
        save_proof(target, d)
        return d

    fn = get_validator(technique)
    if not fn:
        proof.status = "error"
        proof.evidence = f"No validator registered for {technique}. Known: {list_techniques()}"
        proof.finished_at = _now()
        d = proof.to_dict()
        save_proof(target, d)
        return d

    try:
        result = fn(item, pol)
    except Exception as e:
        proof.status = "error"
        proof.evidence = f"{type(e).__name__}: {e}"
        proof.finished_at = _now()
        d = proof.to_dict()
        save_proof(target, d)
        return d

    proof.status = result.get("status") or "error"  # type: ignore[assignment]
    proof.evidence = str(result.get("evidence") or "")
    proof.impact_note = str(result.get("impact_note") or "")
    proof.meta = dict(result.get("meta") or {})
    proof.finished_at = _now()
    d = proof.to_dict()
    save_proof(target, d)
    return d


def run_proofs(
    items: list[dict[str, Any]],
    *,
    policy: dict[str, Any] | None = None,
    scope_check: Callable[[str], bool] | None = None,
    on_progress: Callable[[int, int, dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    pol = policy or load_policy()
    max_n = int(pol.get("max_per_run") or 40)
    items = items[:max_n]
    results: list[dict[str, Any]] = []
    total = len(items)
    for i, item in enumerate(items, 1):
        p = run_one(item, policy=pol, scope_check=scope_check)
        results.append(p)
        if on_progress:
            on_progress(i, total, p)
    return results


def summarize_results(results: list[dict[str, Any]]) -> str:
    counts: dict[str, int] = {}
    for r in results:
        s = r.get("status") or "?"
        counts[s] = counts.get(s, 0) + 1
    lines = [f"proofs: {len(results)}  {counts}"]
    for r in results[:20]:
        lines.append(
            f"  [{r.get('status')}] {r.get('technique')}  "
            f"{(r.get('title') or '')[:36]}  {(r.get('asset') or '')[:40]}"
        )
    if len(results) > 20:
        lines.append(f"  … +{len(results) - 20} more")
    return "\n".join(lines)


def list_saved_proofs(target: str) -> list[dict[str, Any]]:
    return load_proofs(target)
