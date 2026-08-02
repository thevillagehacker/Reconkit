"""
Scan reconkit output directories and build a unified findings index.

This is read-only against scan artifacts — it never mutates recon results.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .history import snapshot_all_from_index
from .models import SEVERITY_RANK, Finding, TargetSummary
from .scoring import NOTABLE_THRESHOLD, enrich, sort_key
from .store import OUTPUT_DIR, load_index, save_index

# Map known filenames → module
FILE_MODULE = {
    "subdomains.txt": "subdomains",
    "dns_records.txt": "dns",
    "cname_takeover_candidates.txt": "dns",
    "alive.txt": "httpprobe",
    "tls_recon.json": "tls",
    "urls.txt": "crawl",
    "js_urls.txt": "js",
    "js_secrets_and_endpoints.json": "js",
    "param_names.txt": "params",
    "arjun_params.txt": "params",
    "sensitive_paths_found.txt": "content",
    "xss_reflected_params.txt": "xss",
    "dalfox_results.txt": "xss",
    "sqli_candidates.txt": "sqli",
    "sqli_error_based.txt": "sqli",
    "sqli_boolean_based.txt": "sqli",
    "ssrf_metadata_candidates.txt": "ssrf_ssti",
    "ssti_candidates.txt": "ssrf_ssti",
    "cloud_assets.json": "cloud",
    "open_s3_buckets.txt": "cloud",
    "agent_report.md": "analyst",
    "agent_state.json": "agents",
    "proofs_index.json": "prove",
}

# Secret category → severity
SECRET_SEVERITY = {
    "aws_keys": "critical",
    "private_keys": "critical",
    "github_tokens": "high",
    "slack_webhooks": "high",
    "discord_webhooks": "medium",
    "google_api_keys": "medium",
    "jwt_tokens": "medium",
    "generic_secrets": "medium",
    "s3_buckets": "low",
    "azure_blobs": "low",
    "gcp_buckets": "low",
    "firebase_urls": "low",
    "internal_ips": "info",
    "emails": "info",
    "graphql_endpoints": "info",
    "hidden_routes": "low",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fid(*parts: str) -> str:
    raw = "|".join(parts)
    return hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


# Tool output (dnsx/httpx/nuclei) often embeds terminal colors. When ESC is lost
# you get UI garbage like: host [[35mCNAME[0m] [[32mfoo.github.io[0m]
_ANSI_RE = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"  # CSI / ESC sequences
    r"|\x9B[0-?]*[ -/]*[@-~]"  # 8-bit CSI
    r"|\[(?:\d{1,3};){0,8}\d{1,3}m"  # orphan SGR e.g. [35m [0m [1;32m
)


def strip_ansi(text: str) -> str:
    """Remove ANSI color/control sequences and orphan SGR leftovers."""
    if not text:
        return ""
    s = _ANSI_RE.sub("", text)
    # leftover bare ESC / C1
    s = s.replace("\x1b", "").replace("\x9b", "")
    # collapse whitespace created by removals (keep single spaces)
    s = re.sub(r"[ \t]{2,}", " ", s)
    return s


def list_targets(output_dir: Path | None = None) -> list[str]:
    root = output_dir or OUTPUT_DIR
    if not root.exists():
        return []
    return sorted(
        p.name for p in root.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    )


def _read_text(path: Path) -> str:
    """Read text; utf-8-sig strips Windows BOM; strip tool ANSI colors."""
    try:
        raw = path.read_text(encoding="utf-8-sig", errors="replace")
    except Exception:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""
    return strip_ansi(raw)


def _read_lines(path: Path, limit: int = 50_000) -> list[str]:
    text = _read_text(path)
    if not text:
        return []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return lines[:limit]


def _guess_module(name: str) -> str:
    if name in FILE_MODULE:
        return FILE_MODULE[name]
    if name.startswith("nuclei") and name.endswith(".txt"):
        return "nuclei"
    if name.startswith("ffuf_") and name.endswith(".json"):
        return "content"
    return "other"


def _severity_for_nuclei_line(line: str) -> str:
    low = line.lower()
    for sev in ("critical", "high", "medium", "low", "info"):
        if f"[{sev}]" in low or f"severity:{sev}" in low or f'"{sev}"' in low:
            return sev
    if "cve-" in low:
        return "high"
    return "medium"


def _parse_alive_line(line: str) -> tuple[str, str, dict[str, Any]]:
    """httpx lines vary; keep full line as evidence, first token as asset."""
    parts = line.split()
    asset = parts[0] if parts else line
    meta: dict[str, Any] = {}
    # common: URL [status] [title]
    m = re.search(r"\[(\d{3})\]", line)
    if m:
        meta["status"] = int(m.group(1))
    return asset, line, meta


def index_target(target: str, output_dir: Path | None = None) -> tuple[TargetSummary, list[Finding]]:
    root = output_dir or OUTPUT_DIR
    outdir = root / target.replace("*", "_")
    findings: list[Finding] = []

    if not outdir.exists():
        return TargetSummary(target=target, outdir=str(outdir)), findings

    files: list[str] = []
    mtime = outdir.stat().st_mtime
    has_agent = (outdir / "agent_state.json").exists()
    has_report = (outdir / "agent_report.md").exists()

    for path in sorted(outdir.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(outdir)).replace("\\", "/")
        files.append(rel)
        # skip huge binaries / screenshots blobs listing only
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".html"}:
            if "screenshot" in rel.lower():
                findings.append(Finding(
                    id=_fid(target, "screenshot", rel),
                    target=target,
                    module="screenshots",
                    ftype="other",
                    title=f"Screenshot: {path.name}",
                    asset=rel,
                    severity="info",
                    evidence=rel,
                    source_file=rel,
                    tags=["screenshot"],
                ))
            continue
        if path.name in ("agent_state.json", "agent_report.md", "findings_index.json"):
            continue
        if path.stat().st_size > 8_000_000:
            continue

        module = _guess_module(path.name)
        findings.extend(_parse_file(target, path, rel, module))

    summary = _summarize(target, str(outdir), findings, files, has_agent, has_report, mtime)
    return summary, findings


def _parse_file(target: str, path: Path, rel: str, module: str) -> list[Finding]:
    name = path.name
    out: list[Finding] = []

    # --- JSON specials ---
    if name == "js_secrets_and_endpoints.json":
        try:
            data = json.loads(_read_text(path))
        except Exception:
            return out
        if isinstance(data, dict):
            for cat, items in data.items():
                if not isinstance(items, (list, set, tuple)):
                    continue
                sev = SECRET_SEVERITY.get(cat, "medium")
                for item in list(items)[:2000]:
                    s = str(item)
                    out.append(Finding(
                        id=_fid(target, "secret", cat, s),
                        target=target,
                        module="js",
                        ftype="secret",
                        title=f"JS secret/endpoint: {cat}",
                        asset=s[:300],
                        severity=sev,
                        evidence=s[:2000],
                        source_file=rel,
                        tags=["js", cat],
                        meta={"category": cat},
                    ))
        return out

    if name == "cloud_assets.json":
        try:
            data = json.loads(_read_text(path))
        except Exception:
            return out
        items = data if isinstance(data, list) else data.get("assets", data.get("buckets", []))
        if isinstance(data, dict) and not items:
            for k, v in data.items():
                if isinstance(v, list):
                    for item in v[:2000]:
                        s = str(item)
                        out.append(Finding(
                            id=_fid(target, "cloud", k, s),
                            target=target,
                            module="cloud",
                            ftype="cloud",
                            title=f"Cloud asset ({k})",
                            asset=s[:300],
                            severity="low",
                            evidence=s[:2000],
                            source_file=rel,
                            tags=["cloud", k],
                        ))
            return out
        if isinstance(items, list):
            for item in items[:2000]:
                s = json.dumps(item) if isinstance(item, (dict, list)) else str(item)
                out.append(Finding(
                    id=_fid(target, "cloud", s),
                    target=target,
                    module="cloud",
                    ftype="cloud",
                    title="Cloud asset",
                    asset=s[:300],
                    severity="low",
                    evidence=s[:2000],
                    source_file=rel,
                    tags=["cloud"],
                ))
        return out

    if name == "tls_recon.json":
        # may be JSONL or a JSON array/object
        text = _read_text(path).strip()
        records: list[Any] = []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                records = parsed
            elif isinstance(parsed, dict):
                records = [parsed]
        except Exception:
            for ln in text.splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    records.append(json.loads(ln))
                except Exception:
                    out.append(Finding(
                        id=_fid(target, "tls", ln),
                        target=target,
                        module="tls",
                        ftype="tls",
                        title="TLS line",
                        asset=ln[:200],
                        severity="info",
                        evidence=ln[:2000],
                        source_file=rel,
                        tags=["tls"],
                    ))
        for rec in records[:3000]:
            host = ""
            if isinstance(rec, dict):
                host = str(rec.get("host") or rec.get("input") or rec.get("ip") or "")
                title = f"TLS: {host or 'host'}"
                evidence = json.dumps(rec)[:2000]
            else:
                title = "TLS record"
                evidence = str(rec)[:2000]
            out.append(Finding(
                id=_fid(target, "tls", evidence[:200]),
                target=target,
                module="tls",
                ftype="tls",
                title=title,
                asset=host or evidence[:200],
                severity="info",
                evidence=evidence,
                source_file=rel,
                tags=["tls"],
            ))
        return out

    if name.startswith("ffuf_") and name.endswith(".json"):
        try:
            data = json.loads(_read_text(path))
        except Exception:
            return out
        results = data.get("results", data if isinstance(data, list) else [])
        if not isinstance(results, list):
            return out
        for r in results[:3000]:
            if not isinstance(r, dict):
                continue
            url = str(r.get("url") or r.get("input", {}).get("FUZZ") or "")
            status = r.get("status") or r.get("status_code")
            out.append(Finding(
                id=_fid(target, "ffuf", url, str(status)),
                target=target,
                module="content",
                ftype="url",
                title=f"ffuf hit [{status}]",
                asset=url,
                severity="low" if status in (200, 301, 302, 401, 403) else "info",
                evidence=json.dumps(r)[:2000],
                source_file=rel,
                tags=["ffuf", "content"],
                meta={"status": status},
            ))
        return out

    # --- line-based text ---
    lines = _read_lines(path)
    if not lines:
        return out

    if name == "subdomains.txt":
        for ln in lines:
            out.append(Finding(
                id=_fid(target, "sub", ln),
                target=target,
                module="subdomains",
                ftype="subdomain",
                title="Subdomain",
                asset=ln,
                severity="info",
                evidence=ln,
                source_file=rel,
                tags=["subdomain"],
            ))
        return out

    if name == "alive.txt":
        for ln in lines:
            asset, evidence, meta = _parse_alive_line(ln)
            out.append(Finding(
                id=_fid(target, "alive", asset),
                target=target,
                module="httpprobe",
                ftype="host",
                title="Alive host",
                asset=asset,
                severity="info",
                evidence=evidence,
                source_file=rel,
                tags=["alive", "http"],
                meta=meta,
            ))
        return out

    if name == "urls.txt" or name == "js_urls.txt":
        ftype = "url"
        mod = "crawl" if name == "urls.txt" else "js"
        tag = "url" if name == "urls.txt" else "js-url"
        # Cap very large URL lists for UI performance; full file still on disk
        for ln in lines[:15_000]:
            out.append(Finding(
                id=_fid(target, tag, ln),
                target=target,
                module=mod,
                ftype=ftype,
                title="JS URL" if mod == "js" else "Crawled URL",
                asset=ln[:500],
                severity="info",
                evidence=ln[:2000],
                source_file=rel,
                tags=[tag],
            ))
        return out

    if name == "cname_takeover_candidates.txt":
        for ln in lines:
            out.append(Finding(
                id=_fid(target, "takeover", ln),
                target=target,
                module="dns",
                ftype="vuln",
                title="CNAME takeover candidate",
                asset=ln[:300],
                severity="high",
                evidence=ln,
                source_file=rel,
                tags=["takeover", "dns"],
            ))
        return out

    if name == "open_s3_buckets.txt":
        for ln in lines:
            out.append(Finding(
                id=_fid(target, "s3open", ln),
                target=target,
                module="cloud",
                ftype="cloud",
                title="Open S3 bucket (public list?)",
                asset=ln[:300],
                severity="high",
                evidence=ln,
                source_file=rel,
                tags=["s3", "cloud", "public"],
            ))
        return out

    if name == "sensitive_paths_found.txt":
        for ln in lines:
            out.append(Finding(
                id=_fid(target, "sensitive", ln),
                target=target,
                module="content",
                ftype="vuln",
                title="Sensitive path",
                asset=ln[:400],
                severity="medium",
                evidence=ln,
                source_file=rel,
                tags=["sensitive", "content"],
            ))
        return out

    if name in ("xss_reflected_params.txt", "dalfox_results.txt"):
        for ln in lines:
            out.append(Finding(
                id=_fid(target, "xss", ln),
                target=target,
                module="xss",
                ftype="vuln",
                title="XSS candidate (detection)",
                asset=ln[:400],
                severity="medium",
                evidence=ln[:2000],
                source_file=rel,
                tags=["xss"],
            ))
        return out

    if name.startswith("sqli") or name in ("ssrf_metadata_candidates.txt", "ssti_candidates.txt"):
        sev = "medium"
        label = "Injection/SSRF/SSTI candidate"
        if "ssrf" in name:
            label = "SSRF metadata candidate"
            sev = "high"
        elif "ssti" in name:
            label = "SSTI candidate"
            sev = "high"
        elif "sqli" in name:
            label = "SQLi candidate"
            sev = "high"
        for ln in lines:
            out.append(Finding(
                id=_fid(target, name, ln),
                target=target,
                module=_guess_module(name),
                ftype="vuln",
                title=label,
                asset=ln[:400],
                severity=sev,
                evidence=ln[:2000],
                source_file=rel,
                tags=[module],
            ))
        return out

    if name.startswith("nuclei") and name.endswith(".txt"):
        for ln in lines:
            sev = _severity_for_nuclei_line(ln)
            out.append(Finding(
                id=_fid(target, "nuclei", ln),
                target=target,
                module="nuclei",
                ftype="vuln",
                title="Nuclei finding",
                asset=ln[:400],
                severity=sev,
                evidence=ln[:2000],
                source_file=rel,
                tags=["nuclei", sev],
            ))
        return out

    if name in ("param_names.txt", "arjun_params.txt", "dns_records.txt"):
        ftype = "param" if "param" in name else "other"
        title = "Parameter" if ftype == "param" else "DNS record"
        for ln in lines[:10_000]:
            out.append(Finding(
                id=_fid(target, name, ln),
                target=target,
                module=module,
                ftype=ftype,
                title=title,
                asset=ln[:300],
                severity="info",
                evidence=ln[:2000],
                source_file=rel,
                tags=[module],
            ))
        return out

    # generic text fallback (small files only)
    if len(lines) <= 500 and path.suffix in (".txt", ".md", ".log", ""):
        for ln in lines[:200]:
            out.append(Finding(
                id=_fid(target, rel, ln),
                target=target,
                module=module,
                ftype="other",
                title=f"{name}",
                asset=ln[:300],
                severity="info",
                evidence=ln[:2000],
                source_file=rel,
                tags=[module, "raw"],
            ))
    return out


def _summarize(
    target: str,
    outdir: str,
    findings: list[Finding],
    files: list[str],
    has_agent: bool,
    has_report: bool,
    mtime: float,
) -> TargetSummary:
    by_module: Counter[str] = Counter()
    by_sev: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    for f in findings:
        by_module[f.module] += 1
        by_sev[f.severity] += 1
        by_type[f.ftype] += 1
    return TargetSummary(
        target=target,
        outdir=outdir,
        finding_count=len(findings),
        by_module=dict(by_module),
        by_severity=dict(by_sev),
        by_type=dict(by_type),
        files=files,
        has_agent_state=has_agent,
        has_report=has_report,
        mtime=mtime,
    )


def index_all_targets(output_dir: Path | None = None, *, persist: bool = True) -> dict[str, Any]:
    root = output_dir or OUTPUT_DIR
    targets = list_targets(root)
    all_findings: list[Finding] = []
    summaries: dict[str, Any] = {}

    for t in targets:
        summary, findings = index_target(t, root)
        summaries[t] = summary.to_dict()
        all_findings.extend(findings)

    # Enrich with scores, sort notable/score first
    dicts = [enrich(f.to_dict()) for f in all_findings]
    dicts.sort(key=sort_key)
    notable_n = sum(1 for d in dicts if d.get("notable"))

    fp = output_fingerprint(root)
    payload = {
        "version": "2.1.0",
        "generated_at": _now(),
        "output_dir": str(root),
        "target_count": len(targets),
        "finding_count": len(dicts),
        "record_count": len(dicts),
        "notable_count": notable_n,
        "notable_threshold": NOTABLE_THRESHOLD,
        "targets": summaries,
        "findings": dicts,
        "records": dicts,
        "output_fingerprint": fp.get("token"),
    }
    if persist:
        save_index(payload)
        try:
            snapshot_all_from_index(payload)
        except Exception:
            pass
    return payload


def _as_finding_dict(f: Finding | dict[str, Any]) -> dict[str, Any]:
    return f.to_dict() if isinstance(f, Finding) else dict(f)


def match_finding(
    d: dict[str, Any],
    *,
    target: str | None = None,
    module: str | None = None,
    severity: str | None = None,
    ftype: str | None = None,
    q: str | None = None,
    notable: bool | None = None,
    min_score: int | None = None,
) -> bool:
    """Return True if record matches all provided filters (empty filter = match)."""
    if target and str(d.get("target") or "") != target:
        return False
    if module and str(d.get("module") or "") != module:
        return False
    if severity and str(d.get("severity") or "").lower() != severity.lower():
        return False
    if ftype and str(d.get("ftype") or "") != ftype:
        return False
    if notable is True and not d.get("notable"):
        return False
    if min_score is not None and int(d.get("score") or 0) < min_score:
        return False
    if q:
        blob = " ".join(
            str(d.get(k, ""))
            for k in ("title", "asset", "evidence", "module", "ftype", "target")
        ).lower()
        if q.lower() not in blob:
            return False
    return True


def filter_findings(
    findings: Iterable[dict[str, Any]] | Iterable[Finding],
    *,
    target: str | None = None,
    module: str | None = None,
    severity: str | None = None,
    ftype: str | None = None,
    q: str | None = None,
    notable: bool | None = None,
    min_score: int | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for f in findings:
        d = _as_finding_dict(f)
        if not match_finding(
            d,
            target=target,
            module=module,
            severity=severity,
            ftype=ftype,
            q=q,
            notable=notable,
            min_score=min_score,
        ):
            continue
        rows.append(d)

    if offset < 0:
        offset = 0
    if limit < 0:
        limit = 0
    return rows[offset: offset + limit]


def filter_stats(
    findings: Iterable[dict[str, Any]] | Iterable[Finding],
    *,
    target: str | None = None,
    module: str | None = None,
    severity: str | None = None,
    ftype: str | None = None,
    q: str | None = None,
    notable: bool | None = None,
    min_score: int | None = None,
) -> dict[str, Any]:
    """Counts for the filtered set (for dashboard KPIs while filters are active)."""
    by_sev: dict[str, int] = {}
    by_mod: dict[str, int] = {}
    by_type: dict[str, int] = {}
    total = 0
    notable_n = 0
    for f in findings:
        d = _as_finding_dict(f)
        if not match_finding(
            d,
            target=target,
            module=module,
            severity=severity,
            ftype=ftype,
            q=q,
            notable=notable,
            min_score=min_score,
        ):
            continue
        total += 1
        if d.get("notable"):
            notable_n += 1
        sev = str(d.get("severity") or "unknown")
        mod = str(d.get("module") or "other")
        tp = str(d.get("ftype") or "other")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_mod[mod] = by_mod.get(mod, 0) + 1
        by_type[tp] = by_type.get(tp, 0) + 1
    return {
        "total": total,
        "notable_count": notable_n,
        "by_severity": by_sev,
        "by_module": by_mod,
        "by_type": by_type,
    }


def output_fingerprint(output_dir: Path | None = None) -> dict[str, Any]:
    """Cheap signature of ~/.reconkit/output so the dashboard can detect new scans.

    Counts targets/files and tracks newest mtime. Does not parse file contents.
    """
    root = output_dir or OUTPUT_DIR
    targets = list_targets(root)
    file_count = 0
    newest = 0.0
    if root.exists():
        try:
            newest = max(newest, root.stat().st_mtime)
        except OSError:
            pass
        for t in targets:
            tdir = root / t
            try:
                newest = max(newest, tdir.stat().st_mtime)
            except OSError:
                pass
            try:
                for p in tdir.rglob("*"):
                    if p.is_file():
                        file_count += 1
                        try:
                            newest = max(newest, p.stat().st_mtime)
                        except OSError:
                            pass
            except OSError:
                pass
    # Stable short token for clients to compare
    token = f"{len(targets)}:{file_count}:{int(newest * 1000)}"
    return {
        "token": token,
        "target_count": len(targets),
        "file_count": file_count,
        "newest_mtime": newest,
        "output_dir": str(root),
    }


def get_or_build_index(*, refresh: bool = False) -> dict[str, Any]:
    """Load disk index, or rebuild from scan output.

    When refresh=False, still rebuild if the on-disk index is missing/empty
    OR if output fingerprint no longer matches the one stored in the index
    (new scans written while the dashboard was running).
    """
    fp = output_fingerprint()
    if not refresh:
        idx = load_index()
        if (
            idx.get("findings") is not None
            and idx.get("generated_at")
            and idx.get("output_fingerprint") == fp.get("token")
        ):
            return idx
        # Stale or missing index — fall through to rebuild
    return index_all_targets(persist=True)
