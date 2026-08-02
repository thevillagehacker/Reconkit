"""
Structured finding evaluation (FP kill + confidence tier) for agents.

Uses skill rules locally first (zero tokens), optional LLM for borderline cases.
"""

from __future__ import annotations

import re
from typing import Any

from .llm import LLMClient
from .skills import skill_system_block

# Instant C0 patterns (substring match on title+evidence+module)
_C0_PATTERNS = [
    r"\bmissing (csp|hsts|x-frame)\b",
    r"\bspf\b.*\bmissing\b",
    r"\bgraphql introspection\b",
    r"\bversion disclosure\b",
    r"\bself-?xss\b",
    r"\blogout csrf\b",
    r"\bmixed content\b",
    r"\bclickjacking\b",
    r"\bopen redirect\b",
    r"\bnuclei.*\binfo\b",
    r"\bcookie (flags|httponly|secure) only\b",
]


def _blob(f: dict[str, Any]) -> str:
    return " ".join(
        str(f.get(k, ""))
        for k in ("title", "evidence", "module", "ftype", "severity", "asset")
    ).lower()


def heuristic_tier(finding: dict[str, Any]) -> dict[str, Any]:
    """Fast local eval — no LLM."""
    b = _blob(finding)
    sev = str(finding.get("severity") or "info").lower()
    score = int(finding.get("score") or 0)
    mod = str(finding.get("module") or "").lower()

    for pat in _C0_PATTERNS:
        if re.search(pat, b):
            return {
                "tier": "C0",
                "why": f"matches kill pattern {pat}",
                "next": "drop",
                "method": "heuristic",
            }

    if sev == "info" and score < 40:
        return {"tier": "C0", "why": "info + low score", "next": "drop", "method": "heuristic"}

    # Strong candidates
    if any(k in b for k in ("takeover", "akia", "private key", "-----begin")):
        return {
            "tier": "C1",
            "why": "high-value keyword",
            "next": "prove:takeover_fingerprint" if "takeover" in b else "manual",
            "method": "heuristic",
        }
    if mod == "xss" or "xss" in b or "dalfox" in b:
        return {
            "tier": "C1",
            "why": "xss candidate",
            "next": "prove:xss_reflect",
            "method": "heuristic",
        }
    if mod == "sqli" or "sqli" in b:
        return {
            "tier": "C1",
            "why": "sqli candidate",
            "next": "prove:sqli_boolean",
            "method": "heuristic",
        }
    if "ssrf" in b:
        return {
            "tier": "C1",
            "why": "ssrf candidate",
            "next": "prove:ssrf_canary_review",
            "method": "heuristic",
        }
    if "ssti" in b:
        return {
            "tier": "C1",
            "why": "ssti candidate",
            "next": "prove:ssti_math",
            "method": "heuristic",
        }
    if mod == "nuclei" or "cve-" in b:
        return {
            "tier": "C1",
            "why": "nuclei/cve candidate",
            "next": "prove:nuclei_recheck",
            "method": "heuristic",
        }
    if score >= 75:
        return {"tier": "C1", "why": "high score", "next": "manual", "method": "heuristic"}
    if score >= 40:
        return {"tier": "C1", "why": "notable score", "next": "manual", "method": "heuristic"}
    return {"tier": "C0", "why": "low signal", "next": "drop", "method": "heuristic"}


def evaluate_findings(
    findings: list[dict[str, Any]],
    *,
    limit: int = 15,
    use_llm: bool = False,
    llm: LLMClient | None = None,
) -> list[dict[str, Any]]:
    """
    Evaluate top findings. Heuristic always; optional LLM for borderline C1.
    Returns list of {finding_id, title, tier, why, next, ...}
    """
    ranked = sorted(findings, key=lambda f: -int(f.get("score") or 0))[:limit]
    out: list[dict[str, Any]] = []
    for f in ranked:
        ev = heuristic_tier(f)
        row = {
            "finding_id": f.get("id"),
            "title": f.get("title"),
            "asset": (f.get("asset") or "")[:120],
            "score": f.get("score"),
            "module": f.get("module"),
            **ev,
        }
        out.append(row)

    if use_llm and llm is not None:
        borderline = [r for r in out if r.get("tier") == "C1"][:5]
        if borderline:
            try:
                system = (
                    "You classify bug bounty findings. Reply with lines: "
                    "ID=<id> TIER=C0|C1|C2 NEXT=drop|prove:tech|manual WHY=words\n"
                    "Never invent C3/C4 without proof."
                )
                skill = skill_system_block(role="critic", max_chars=4000)
                if skill:
                    system += "\n" + skill
                user = "Findings:\n" + "\n".join(
                    f"- id={r['finding_id']} score={r['score']} mod={r['module']} "
                    f"title={r['title']} asset={r['asset']}"
                    for r in borderline
                )
                text = llm.chat(
                    [{"role": "system", "content": system}, {"role": "user", "content": user}],
                    temperature=0.1,
                )
                by_id = {r["finding_id"]: r for r in out}
                for line in text.splitlines():
                    m = re.search(
                        r"ID[=:\s]+(\S+).*TIER[=:\s]+(C[0-4]).*NEXT[=:\s]+(\S+)",
                        line,
                        re.I,
                    )
                    if not m:
                        continue
                    fid, tier, nxt = m.group(1), m.group(2).upper(), m.group(3)
                    # strip punctuation
                    fid = fid.strip(" ,;")
                    if fid in by_id:
                        by_id[fid]["tier"] = tier
                        by_id[fid]["next"] = nxt
                        by_id[fid]["method"] = "heuristic+llm"
                        why = re.search(r"WHY[=:\s]+(.+)$", line, re.I)
                        if why:
                            by_id[fid]["why"] = why.group(1).strip()[:120]
            except Exception:
                pass
    return out


def format_eval_report(rows: list[dict[str, Any]]) -> str:
    lines = ["# Finding evaluation", ""]
    for r in rows:
        lines.append(
            f"- **{r.get('tier')}** `{r.get('finding_id')}` {r.get('title')} → `{r.get('next')}` "
            f"({r.get('why')})"
        )
    return "\n".join(lines) + "\n"
