"""Assign C0–C4 confidence and workflow status on every recon record.

C0 inventory / noise — hide by default
C1 scanner candidate — needs /prove or manual
C2 canary confirmed by prove
C3 impact (human)
C4 report-ready
"""

from __future__ import annotations

from typing import Any

TIERS = ("C0", "C1", "C2", "C3", "C4")
STATUSES = ("inventory", "candidate", "needs_prove", "confirmed", "false_positive", "manual")

_INVENTORY_TYPES = {"subdomain", "host", "url", "param", "tls", "other"}
_CANDIDATE_MODULES = {
    "xss", "sqli", "ssrf_ssti", "nuclei",
    "cors", "graphql", "redirect", "bypass403", "apis", "takeover_plus",
}
_CANDIDATE_TYPES = {"vuln", "secret", "cloud"}


def assign_confidence(d: dict[str, Any]) -> dict[str, Any]:
    """Set confidence + status on a finding dict (mutates and returns it)."""
    existing = str(d.get("confidence") or "").upper()
    if existing in TIERS and d.get("status"):
        return d

    ftype = str(d.get("ftype") or "other").lower()
    module = str(d.get("module") or "").lower()
    sev = str(d.get("severity") or "info").lower()
    title = str(d.get("title") or "").lower()
    tags = [str(t).lower() for t in (d.get("tags") or [])]
    score = int(d.get("score") or 0)

    if module in ("screenshots",) or ftype in _INVENTORY_TYPES and sev in ("info", "unknown"):
        if module not in _CANDIDATE_MODULES and ftype not in _CANDIDATE_TYPES:
            d["confidence"] = "C0"
            d["status"] = "inventory"
            return d

    if ftype == "secret" and sev in ("critical", "high"):
        d["confidence"] = "C1"
        d["status"] = "needs_prove"
        return d

    if module in _CANDIDATE_MODULES or ftype in _CANDIDATE_TYPES or "takeover" in title or "takeover" in tags:
        d["confidence"] = "C1"
        d["status"] = "candidate"
        return d

    if sev in ("critical", "high") or score >= 75:
        d["confidence"] = "C1"
        d["status"] = "candidate"
        return d

    if sev == "medium" or score >= 40:
        d["confidence"] = "C1"
        d["status"] = "candidate"
        return d

    d["confidence"] = "C0"
    d["status"] = "inventory"
    return d


def apply_proof_confidence(d: dict[str, Any], proof: dict[str, Any] | None) -> dict[str, Any]:
    """Upgrade a finding from a matching proof record."""
    if not proof:
        return d
    st = str(proof.get("status") or "").lower()
    if st == "confirmed":
        d["confidence"] = "C2"
        d["status"] = "confirmed"
        d["proof_id"] = proof.get("id")
    elif st in ("false_positive", "not_exploitable"):
        d["confidence"] = "C0"
        d["status"] = "false_positive"
        d["proof_id"] = proof.get("id")
    elif st in ("needs_manual",):
        d["status"] = "manual"
        d.setdefault("confidence", "C1")
        d["proof_id"] = proof.get("id")
    return d


def merge_proofs_into_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """If proofs exist, lift matching findings to C2 / mark FPs."""
    try:
        from prove.store import load_all_proofs
    except Exception:
        return findings
    by_fid: dict[str, dict[str, Any]] = {}
    try:
        for p in load_all_proofs(None):
            fid = str(p.get("finding_id") or "")
            if not fid:
                continue
            prev = by_fid.get(fid)
            if prev is None or _rank(p) >= _rank(prev):
                by_fid[fid] = p
    except Exception:
        return findings
    if not by_fid:
        return findings
    for d in findings:
        p = by_fid.get(str(d.get("id") or ""))
        if p:
            apply_proof_confidence(d, p)
    return findings


def _rank(p: dict[str, Any]) -> int:
    st = str(p.get("status") or "")
    return {"confirmed": 3, "false_positive": 2, "not_exploitable": 2, "needs_manual": 1}.get(st, 0)
