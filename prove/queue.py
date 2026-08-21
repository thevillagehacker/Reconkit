"""Build a safe-validation queue from the findings index."""

from __future__ import annotations

from typing import Any

from findings.scoring import NOTABLE_THRESHOLD, is_notable
from findings.store import load_index

from .policy import load_policy


def _map_technique(finding: dict[str, Any]) -> str | None:
    """Map a recon finding to a safe validator technique, or None if not provable."""
    mod = str(finding.get("module") or "").lower()
    ftype = str(finding.get("ftype") or "").lower()
    title = str(finding.get("title") or "").lower()
    source = str(finding.get("source_file") or "").lower()
    # Ignore the combined module name `ssrf_ssti` — it contains both tokens.
    blob = f"{ftype} {title} {source} {finding.get('asset', '')}".lower()

    if mod == "xss" or "xss" in title or "dalfox" in blob or "xss" in source:
        return "xss_reflect"
    if "ssti" in source or "ssti" in title:
        return "ssti_math"
    if "ssrf" in source or "ssrf" in title or mod == "ssrf_ssti":
        return "ssrf_canary_review"
    if mod == "nuclei" or "nuclei" in source or (ftype == "vuln" and "cve" in blob):
        return "nuclei_recheck"
    if mod == "dns" and ("takeover" in blob or "cname" in blob):
        return "takeover_fingerprint"
    if "takeover" in title:
        return "takeover_fingerprint"
    # sqli: only queued when policy allows boolean canary (checked at run time too)
    if mod == "sqli" or "sqli" in title or "sqli" in source:
        return "sqli_boolean"
    if mod == "jwt" or "jwt" in title or "jwt" in source:
        return "jwt_inspect"
    if mod == "cors" or "cors" in title or "cors" in source:
        return "cors_origin"
    if mod == "graphql" or "graphql" in title or "graphql" in source:
        return "graphql_typename"
    if mod == "redirect" or "redirect_hits" in source:
        return "redirect_canary"
    if mod == "idor" or "idor" in title or "idor_candidates" in source:
        return "idor_session_diff"
    if mod == "takeover_plus":
        return None
    if "takeover" in source:
        return "takeover_fingerprint"
    return None


def build_queue(
    *,
    target: str | None = None,
    notable_only: bool = True,
    threshold: int = NOTABLE_THRESHOLD,
    techniques: list[str] | None = None,
    limit: int | None = None,
    include_unmapped: bool = False,
) -> list[dict[str, Any]]:
    """
    Return queue items:
      {finding, technique, risk_class, reason}
    """
    pol = load_policy()
    allowed = set(pol.get("allowed_techniques") or [])
    if techniques:
        allowed &= set(techniques)
    max_n = limit if limit is not None else int(pol.get("max_per_run") or 40)

    findings: list[dict[str, Any]] = []
    used_store = False
    try:
        from findings.indexer import query_store
        findings, _st = query_store(
            target=(target.strip() if target else None),
            notable=True if notable_only else None,
            min_confidence="C1",
            limit=max(max_n * 8, 80),
            offset=0,
        )
        used_store = True
    except Exception:
        findings = []
    if not findings and not used_store:
        payload = load_index()
        findings = list(payload.get("findings") or [])
        if target:
            t = target.strip()
            findings = [f for f in findings if f.get("target") == t]
        if notable_only:
            findings = [f for f in findings if is_notable(f, threshold)]
        findings.sort(key=lambda f: (-int(f.get("score") or 0), f.get("severity") or ""))

    queue: list[dict[str, Any]] = []
    for f in findings:
        tech = _map_technique(f)
        if tech == "sqli_boolean" and not pol.get("allow_sqli_boolean"):
            continue
        if tech and tech in allowed:
            queue.append({
                "finding_id": f.get("id"),
                "target": f.get("target"),
                "technique": tech,
                "risk_class": "safe",
                "title": f.get("title"),
                "asset": f.get("asset"),
                "module": f.get("module"),
                "severity": f.get("severity"),
                "score": f.get("score"),
                "confidence": f.get("confidence"),
                "status": f.get("status"),
                "source_file": f.get("source_file"),
                "evidence": (f.get("evidence") or "")[:400],
                "finding": f,
            })
        elif include_unmapped and (
            f.get("module") in (
                "xss", "sqli", "ssrf_ssti", "nuclei", "dns",
                "cors", "graphql", "redirect", "apis", "bypass403", "takeover_plus",
            )
            or f.get("ftype") == "vuln"
        ):
            queue.append({
                "finding_id": f.get("id"),
                "target": f.get("target"),
                "technique": "manual",
                "risk_class": "safe",
                "title": f.get("title"),
                "asset": f.get("asset"),
                "module": f.get("module"),
                "severity": f.get("severity"),
                "score": f.get("score"),
                "confidence": f.get("confidence"),
                "status": f.get("status"),
                "source_file": f.get("source_file"),
                "evidence": (f.get("evidence") or "")[:400],
                "finding": f,
                "reason": "no safe auto-validator; manual review",
            })
        if len(queue) >= max_n:
            break
    return queue


def queue_summary(items: list[dict[str, Any]]) -> str:
    by_tech: dict[str, int] = {}
    for it in items:
        t = it.get("technique") or "?"
        by_tech[t] = by_tech.get(t, 0) + 1
    lines = [
        f"queue size: {len(items)}",
        f"by technique: {by_tech or '{}'}",
    ]
    for i, it in enumerate(items[:15], 1):
        lines.append(
            f"  {i:2}. [{it.get('score', '?')}] {it.get('confidence') or ''} "
            f"{it.get('technique')} → {(it.get('title') or '')[:36]}  "
            f"{(it.get('asset') or '')[:44]}"
        )
    if len(items) > 15:
        lines.append(f"  … +{len(items) - 15} more")
    return "\n".join(lines)
