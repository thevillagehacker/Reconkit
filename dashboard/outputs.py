"""List recon output files the same way the CLI stores them."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from findings.store import OUTPUT_DIR

SKIP_NAMES = {
    "agent_state.json",
    "findings_index.json",
    ".live_mission.json",
    "live_mission.json",
}

SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip"}

# Canonical merged filenames → pipeline phase
MERGED_PHASE = {
    "subdomains.txt": "subdomains",
    "resolved.txt": "dns",
    "dns_records.txt": "dns",
    "cname_takeover_candidates.txt": "dns",
    "wildcard_dns.txt": "dns",
    "ports.txt": "ports",
    "ports_http.txt": "ports",
    "alive.txt": "httpprobe",
    "alive_urls.txt": "httpprobe",
    "waf_detected.txt": "httpprobe",
    "wildcard_http_dropped.txt": "httpprobe",
    "tls_recon.json": "tls",
    "wellknown.txt": "wellknown",
    "urls.txt": "crawl",
    "js_urls.txt": "js",
    "js_secrets_and_endpoints.json": "js",
    "js_intel.json": "jsintel",
    "api_paths.txt": "jsintel",
    "param_names.txt": "params",
    "arjun_params.txt": "params",
    "arjun_input.txt": "params",
    "api_urls.txt": "apis",
    "idor_candidates.txt": "apis",
    "sensitive_paths_found.txt": "content",
    "bypass403.txt": "bypass403",
    "redirect_candidates.txt": "gfextra",
    "lfi_candidates.txt": "gfextra",
    "interesting_params.txt": "gfextra",
    "xss_reflected_params.txt": "xss",
    "dalfox_results.txt": "xss",
    "sqli_candidates.txt": "sqli",
    "sqli_error_based.txt": "sqli",
    "sqli_boolean_based.txt": "sqli",
    "ssrf_metadata_candidates.txt": "ssrf_ssti",
    "ssti_candidates.txt": "ssrf_ssti",
    "redirect_hits.txt": "redirect",
    "cors_candidates.txt": "cors",
    "graphql_endpoints.txt": "graphql",
    "cloud_assets.json": "cloud",
    "open_s3_buckets.txt": "cloud",
    "takeover_plus.txt": "takeover_plus",
    "osint.txt": "osint",
    "git_urls.txt": "gitrecon",
    "trufflehog.jsonl": "gitrecon",
    "permute_raw.txt": "permute",
    "permute_resolved.txt": "permute",
    "wordlist_target.txt": "content",
}


def _classify(rel: str) -> tuple[str, str, str]:
    """Return (phase, tool, kind) for a path relative to the target outdir."""
    posix = rel.replace("\\", "/")
    name = Path(posix).name
    if posix.startswith("tools/"):
        parts = posix.split("/")
        stage = parts[1] if len(parts) > 1 else "other"
        tool = Path(name).stem
        return stage, tool, "tool"
    if posix.startswith("proofs/") or "/proofs/" in posix:
        return "prove", Path(name).stem, "proof"
    if "screenshot" in posix.lower():
        return "screenshots", "gowitness", "binary"
    if name.startswith("nuclei") and name.endswith(".txt"):
        return "nuclei", Path(name).stem, "merged"
    if name.startswith("ffuf_"):
        return "content", "ffuf", "merged"
    phase = MERGED_PHASE.get(name, "other")
    return phase, "merged", "merged"


def list_output_files(target: str) -> dict[str, Any]:
    tdir = (OUTPUT_DIR / target.replace("*", "_")).resolve()
    base = OUTPUT_DIR.resolve()
    try:
        tdir.relative_to(base)
    except ValueError:
        return {"error": "invalid target", "files": []}
    if not tdir.is_dir():
        return {"target": target, "outdir": str(tdir), "files": [], "phases": [], "tools": []}

    files: list[dict[str, Any]] = []
    phases: set[str] = set()
    tools: set[str] = set()
    for path in sorted(tdir.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(tdir)).replace("\\", "/")
        if path.name in SKIP_NAMES or path.name.startswith("."):
            continue
        if path.suffix.lower() in SKIP_SUFFIX:
            continue
        phase, tool, kind = _classify(rel)
        phases.add(phase)
        tools.add(tool)
        size = path.stat().st_size
        lines = 0
        if size < 4_000_000 and path.suffix.lower() in {".txt", ".json", ".jsonl", ".md", ".log", ""}:
            try:
                lines = sum(1 for ln in path.open("r", encoding="utf-8", errors="replace") if ln.strip())
            except Exception:
                lines = 0
        files.append({
            "path": rel,
            "name": path.name,
            "phase": phase,
            "tool": tool,
            "kind": kind,
            "size": size,
            "lines": lines,
            "mtime": path.stat().st_mtime,
        })
    return {
        "target": target,
        "outdir": str(tdir),
        "files": files,
        "phases": sorted(phases),
        "tools": sorted(tools),
        "count": len(files),
    }


def read_output_file(target: str, rel: str, max_chars: int = 200_000) -> dict[str, Any]:
    tdir = (OUTPUT_DIR / target.replace("*", "_")).resolve()
    rel_path = Path(rel.replace("\\", "/"))
    if ".." in rel_path.parts:
        return {"error": "invalid path"}
    full = (tdir / rel_path).resolve()
    try:
        full.relative_to(tdir)
    except ValueError:
        return {"error": "path outside target dir"}
    if not full.is_file():
        return {"error": "file not found"}
    if full.stat().st_size > 4_000_000:
        return {"error": "file too large", "size": full.stat().st_size}
    text = full.read_text(encoding="utf-8-sig", errors="replace")
    phase, tool, kind = _classify(rel)
    return {
        "target": target,
        "path": rel.replace("\\", "/"),
        "phase": phase,
        "tool": tool,
        "kind": kind,
        "size": full.stat().st_size,
        "content": text[:max_chars],
        "truncated": len(text) > max_chars,
    }
