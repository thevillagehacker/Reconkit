"""
Heuristic scoring for recon records + optional program bounty weights (v2.2).

Higher score = more interesting for a hunter. Used for:
  - sorting index
  - "notable only" dashboard/shell views
  - report drafts
  - prove queue ordering
"""

from __future__ import annotations

from typing import Any

from .models import SEVERITY_RANK

# Base points by severity label
_SEV_SCORE = {
    "critical": 100,
    "high": 75,
    "medium": 45,
    "low": 20,
    "info": 5,
    "unknown": 8,
}

# Bonus by record type
_TYPE_SCORE = {
    "vuln": 25,
    "secret": 30,
    "cloud": 15,
    "host": 2,
    "url": 1,
    "param": 3,
    "tls": 4,
    "subdomain": 1,
    "other": 0,
}

# Title / evidence / tag keyword bumps (case-insensitive substrings)
_KEYWORD_BONUS = [
    ("takeover", 35),
    ("cname", 10),
    ("aws", 20),
    ("akia", 40),
    ("private key", 40),
    ("-----begin", 40),
    ("jwt", 12),
    ("webhook", 15),
    ("admin", 8),
    ("internal", 6),
    (".env", 25),
    (".git", 25),
    ("ssrf", 20),
    ("ssti", 20),
    ("sqli", 18),
    ("xss", 12),
    ("cve-", 15),
    ("exposed", 12),
    ("s3", 10),
    ("firebase", 8),
    ("graphql", 5),
    ("idor", 18),
    ("bola", 18),
]

# Minimum score to count as "notable" by default
NOTABLE_THRESHOLD = 40


def base_score_finding(d: dict[str, Any]) -> int:
    """Compute base integer score before program weights."""
    sev = str(d.get("severity") or "info").lower()
    ftype = str(d.get("ftype") or "other").lower()
    score = _SEV_SCORE.get(sev, 8) + _TYPE_SCORE.get(ftype, 0)

    blob = " ".join(
        str(d.get(k, ""))
        for k in ("title", "asset", "evidence", "module")
    ).lower()
    tags = " ".join(str(t) for t in (d.get("tags") or [])).lower()
    blob = blob + " " + tags

    for kw, pts in _KEYWORD_BONUS:
        if kw in blob:
            score += pts

    return min(score, 200)


def score_finding(d: dict[str, Any], *, apply_program: bool = True) -> int:
    """Compute integer score; applies active program weights when available."""
    base = base_score_finding(d)
    if not apply_program:
        return base
    try:
        from programs.profiles import apply_program_score

        weighted, _meta = apply_program_score(base, d)
        return weighted
    except Exception:
        return base


def is_notable(d: dict[str, Any], threshold: int | None = None) -> bool:
    if threshold is None:
        threshold = _active_threshold()
    s = d.get("score")
    if s is None:
        s = score_finding(d)
    return int(s) >= int(threshold)


def _active_threshold() -> int:
    try:
        from programs.profiles import get_active_profile

        t = get_active_profile().get("notable_threshold")
        if t is not None:
            return int(t)
    except Exception:
        pass
    return NOTABLE_THRESHOLD


def enrich(d: dict[str, Any], threshold: int | None = None) -> dict[str, Any]:
    """Return copy with score + notable + program meta fields set."""
    out = dict(d)
    base = base_score_finding(out)
    thr = threshold if threshold is not None else _active_threshold()
    try:
        from programs.profiles import apply_program_score, get_active_profile

        weighted, meta = apply_program_score(base, out)
        out["score"] = weighted
        out["base_score"] = base
        out["program"] = meta.get("program")
        out["weight_category"] = meta.get("weight_category")
        out["score_meta"] = meta
        prof = get_active_profile()
        thr = int(prof.get("notable_threshold") or thr)
    except Exception:
        out["score"] = base
        out["base_score"] = base
    out["notable"] = out["score"] >= thr
    return out


def sort_key(d: dict[str, Any]) -> tuple:
    """Sort notable-first, then score desc, then severity rank."""
    thr = _active_threshold()
    score = int(d.get("score") or score_finding(d))
    sev = str(d.get("severity") or "unknown").lower()
    return (
        0 if d.get("notable") or score >= thr else 1,
        -score,
        SEVERITY_RANK.get(sev, 9),
        str(d.get("target") or ""),
        str(d.get("module") or ""),
    )
