"""
Shared recon state passed between agents and the orchestrator.
Persisted to ~/.reconkit/output/<target>/agent_state.json so runs can resume.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# Module dependency graph — an agent may only run a module if prerequisites
# are satisfied (or already present as output files from a prior run).
MODULE_DEPS: dict[str, list[str]] = {
    "subdomains": [],
    "permute": ["subdomains"],
    "dns": ["subdomains"],
    "ports": ["subdomains"],
    "httpprobe": ["subdomains"],
    "tls": ["httpprobe"],
    "wellknown": ["httpprobe"],
    "crawl": ["httpprobe"],
    "js": ["crawl"],
    "jsintel": ["js"],
    "params": ["crawl"],
    "apis": ["crawl"],
    "content": ["httpprobe"],
    "bypass403": ["httpprobe"],
    "gfextra": ["crawl"],
    "xss": ["crawl"],
    "sqli": ["crawl"],
    "ssrf_ssti": ["crawl"],
    "redirect": ["crawl"],
    "cors": ["httpprobe"],
    "graphql": ["crawl"],
    "nuclei": ["httpprobe"],
    "cloud": ["crawl"],
    "takeover_plus": ["crawl"],
    "osint": ["subdomains"],
    "gitrecon": ["crawl"],
    "screenshots": ["httpprobe"],
}

# Key output files each module is expected to produce (for summaries).
MODULE_OUTPUTS: dict[str, list[str]] = {
    "subdomains": ["subdomains.txt"],
    "permute": ["permute_resolved.txt"],
    "dns": ["dns_records.txt", "cname_takeover_candidates.txt"],
    "ports": ["ports.txt"],
    "httpprobe": ["alive.txt"],
    "tls": ["tls_recon.json"],
    "wellknown": ["wellknown.txt"],
    "crawl": ["urls.txt"],
    "js": ["js_urls.txt", "js_secrets_and_endpoints.json"],
    "jsintel": ["js_intel.json"],
    "params": ["param_names.txt", "arjun_params.txt"],
    "apis": ["api_urls.txt", "idor_candidates.txt"],
    "content": ["sensitive_paths_found.txt"],
    "bypass403": ["bypass403.txt"],
    "gfextra": ["redirect_candidates.txt", "lfi_candidates.txt", "interesting_params.txt"],
    "xss": ["xss_reflected_params.txt", "dalfox_results.txt"],
    "sqli": ["sqli_error_based.txt", "sqli_boolean_based.txt"],
    "ssrf_ssti": ["ssrf_metadata_candidates.txt", "ssti_candidates.txt"],
    "redirect": ["redirect_hits.txt"],
    "cors": ["cors_candidates.txt"],
    "graphql": ["graphql_endpoints.txt"],
    "nuclei": [],  # nuclei_*.txt — handled dynamically
    "cloud": ["cloud_assets.json", "open_s3_buckets.txt"],
    "takeover_plus": ["takeover_plus.txt"],
    "osint": ["osint.txt"],
    "gitrecon": ["git_urls.txt"],
    "screenshots": ["screenshots"],
}


@dataclass
class AgentStep:
    agent: str
    modules: list[str]
    reasoning: str
    summary: str
    timestamp: str
    success: bool = True
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconState:
    target: str
    outdir: str
    completed_modules: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)
    findings: dict[str, Any] = field(default_factory=dict)
    status: str = "running"  # running | completed | failed | stopped
    created_at: str = field(default_factory=lambda: _now())
    updated_at: str = field(default_factory=lambda: _now())

    def mark(self, module: str) -> None:
        if module not in self.completed_modules:
            self.completed_modules.append(module)
        self.updated_at = _now()

    def add_step(self, step: AgentStep) -> None:
        self.history.append(asdict(step))
        self.updated_at = _now()

    def remaining_modules(self, all_modules: list[str]) -> list[str]:
        return [m for m in all_modules if m not in self.completed_modules]

    def deps_satisfied(self, module: str) -> bool:
        return all(d in self.completed_modules for d in MODULE_DEPS.get(module, []))

    def runnable_modules(self, all_modules: list[str]) -> list[str]:
        """Modules not yet done whose prerequisites are complete."""
        return [
            m for m in all_modules
            if m not in self.completed_modules and self.deps_satisfied(m)
        ]

    def save(self, path: Path | None = None) -> Path:
        path = path or (Path(self.outdir) / "agent_state.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: Path) -> "ReconState":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)

    @classmethod
    def load_or_create(cls, target: str, outdir: Path) -> "ReconState":
        path = outdir / "agent_state.json"
        if path.exists():
            try:
                st = cls.load(path)
                if st.target == target:
                    # Re-sync completed modules from existing output files
                    st.sync_from_disk()
                    return st
            except Exception:
                pass
        st = cls(target=target, outdir=str(outdir))
        st.sync_from_disk()
        return st

    def sync_from_disk(self) -> None:
        """Mark modules complete if their primary output files already exist and are non-empty."""
        outdir = Path(self.outdir)
        if not outdir.exists():
            return
        for module, files in MODULE_OUTPUTS.items():
            if module in self.completed_modules:
                continue
            if module == "nuclei":
                if any(outdir.glob("nuclei_*.txt")):
                    self.mark(module)
                continue
            if module == "screenshots":
                shot = outdir / "screenshots"
                if shot.exists() and any(shot.iterdir()):
                    self.mark(module)
                continue
            for f in files:
                p = outdir / f
                if p.exists() and p.stat().st_size > 0:
                    self.mark(module)
                    break


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def summarize_file(path: Path, max_lines: int = 30, max_chars: int = 4000) -> dict[str, Any]:
    """Produce a compact summary of an output file for LLM context."""
    if not path.exists():
        return {"path": str(path.name), "exists": False}
    if path.is_dir():
        children = list(path.iterdir())
        return {
            "path": path.name,
            "exists": True,
            "type": "directory",
            "file_count": len(children),
            "sample": [c.name for c in children[:10]],
        }

    size = path.stat().st_size
    if size == 0:
        return {"path": path.name, "exists": True, "lines": 0, "size": 0, "empty": True}

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"path": path.name, "exists": True, "error": str(e), "size": size}

    lines = [ln for ln in text.splitlines() if ln.strip()]
    preview = lines[:max_lines]
    preview_text = "\n".join(preview)
    if len(preview_text) > max_chars:
        preview_text = preview_text[:max_chars] + "\n…(truncated)"

    summary: dict[str, Any] = {
        "path": path.name,
        "exists": True,
        "lines": len(lines),
        "size": size,
        "preview": preview_text,
    }

    # Lightweight signals for interesting findings
    lower = text.lower()
    interesting_keywords = [
        "critical", "high", "takeover", "aws_access", "private key",
        "password", "secret", "api_key", "jwt", "s3://", "reflected",
        "vulnerable", "exposure", "misconfiguration",
    ]
    hits = [k for k in interesting_keywords if k in lower]
    if hits:
        summary["interesting_keywords"] = hits

    return summary


def build_context_bundle(state: ReconState, max_files: int = 12) -> dict[str, Any]:
    """Bundle state + file summaries for the planner / analyst agents."""
    outdir = Path(state.outdir)
    file_summaries: list[dict[str, Any]] = []
    if outdir.exists():
        # Prefer known high-value outputs first
        priority = [
            "subdomains.txt", "alive.txt", "urls.txt", "dns_records.txt",
            "cname_takeover_candidates.txt", "js_secrets_and_endpoints.json",
            "sensitive_paths_found.txt", "xss_reflected_params.txt",
            "dalfox_results.txt", "sqli_error_based.txt", "open_s3_buckets.txt",
            "cloud_assets.json", "param_names.txt",
        ]
        seen: set[str] = set()
        for name in priority:
            p = outdir / name
            if p.exists():
                file_summaries.append(summarize_file(p))
                seen.add(name)
            if len(file_summaries) >= max_files:
                break
        if len(file_summaries) < max_files:
            for p in sorted(outdir.glob("*")):
                if p.name in seen or p.name == "agent_state.json":
                    continue
                if p.is_file() and p.suffix in (".txt", ".json"):
                    file_summaries.append(summarize_file(p))
                    if len(file_summaries) >= max_files:
                        break
        # nuclei results
        for p in sorted(outdir.glob("nuclei_*.txt"))[:3]:
            if len(file_summaries) >= max_files:
                break
            if p.name not in seen:
                file_summaries.append(summarize_file(p))

    return {
        "target": state.target,
        "outdir": state.outdir,
        "completed_modules": state.completed_modules,
        "status": state.status,
        "history_tail": state.history[-5:],
        "findings": state.findings,
        "outputs": file_summaries,
    }


# Counts always shown, including zeros. These decide the next module.
_CORE_COUNTS = (
    "subdomains.txt",
    "resolved.txt",
    "permute_raw.txt",
    "permute_resolved.txt",
    "alive.txt",
    "urls.txt",
    "cname_takeover_candidates.txt",
)
# Shown only when the file has lines.
_EXTRA_COUNTS = (
    "dns_records.txt",
    "gf_xss.txt",
    "gf_sqli.txt",
    "gf_ssrf.txt",
    "gf_ssti.txt",
    "redirect_candidates.txt",
    "lfi_candidates.txt",
    "interesting_params.txt",
    "param_names.txt",
    "param_priority.txt",
    "sensitive_paths_found.txt",
    "js_urls.txt",
    "tech_routes.txt",
    "xss_reflected_params.txt",
    "open_s3_buckets.txt",
)
# ports stays eligible when alive.txt is empty; it does not read that file.
_ALIVE_MODULES = (
    "tls", "wellknown", "crawl", "content", "bypass403",
    "cors", "nuclei", "screenshots",
)
_URL_MODULES = (
    "js", "jsintel", "params", "apis", "gfextra",
    "xss", "sqli", "ssrf_ssti", "redirect", "graphql",
    "cloud", "takeover_plus", "gitrecon",
)
_HEAD_FILES = (
    "cname_takeover_candidates.txt",
    "alive.txt",
    "tech_routes.txt",
    "sensitive_paths_found.txt",
    "xss_reflected_params.txt",
)
_EVIDENCE_FILES = (
    "cname_takeover_candidates.txt",
    "tech_routes.txt",
    "sensitive_paths_found.txt",
    "xss_reflected_params.txt",
    "sqli_error_based.txt",
    "ssti_candidates.txt",
    "ssrf_metadata_candidates.txt",
    "open_s3_buckets.txt",
    "js_secrets_and_endpoints.json",
    "param_priority.txt",
    "cors_candidates.txt",
    "graphql_endpoints.txt",
)


def _nonempty_count(path: Path) -> int:
    if not path.is_file():
        return 0
    count = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                if raw.strip():
                    count += 1
    except OSError:
        return 0
    return count


def _head(path: Path, limit: int = 3, width: int = 160) -> list[str]:
    if not path.is_file() or limit <= 0:
        return []
    rows: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                text = raw.strip()
                if not text:
                    continue
                rows.append(text[:width])
                if len(rows) >= limit:
                    break
    except OSError:
        return []
    return rows


def _has_token(path: Path, token: str, limit: int) -> bool:
    if not path.is_file():
        return False
    needle = token.lower()
    seen = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                if not raw.strip():
                    continue
                seen += 1
                if needle in raw.lower():
                    return True
                if seen >= limit:
                    break
    except OSError:
        return False
    return False


def _in_run(name: str, runnable: list[str] | None) -> bool:
    return runnable is None or name in runnable


def recon_brief(outdir: Path | str, runnable: list[str] | None = None) -> str:
    """Counts, skip rules, and a few head lines. No full file bodies."""
    root = Path(outdir)
    counts = {
        name: _nonempty_count(root / name) if root.is_dir() else 0
        for name in _CORE_COUNTS + _EXTRA_COUNTS
    }
    nuclei_lines = 0
    nuclei_n = 0
    if root.is_dir():
        for path in sorted(root.glob("nuclei_*.txt"))[:8]:
            nuclei_n += 1
            nuclei_lines += _nonempty_count(path)

    lines = ["counts:"]
    lines.append(" ".join(f"{name}={counts[name]}" for name in _CORE_COUNTS))
    extra = [f"{name}={counts[name]}" for name in _EXTRA_COUNTS if counts[name]]
    if extra:
        lines.append(" ".join(extra))
    if nuclei_n:
        lines.append(f"nuclei_files={nuclei_n} nuclei_lines={nuclei_lines}")

    lines.append("notes:")
    lines.append("Unresolved permute names are not hosts. Use resolved.txt and alive.txt.")

    skips: list[str] = []
    reasons: list[str] = []

    def add_skips(names: tuple[str, ...], reason: str) -> None:
        picked = [name for name in names if _in_run(name, runnable)]
        if not picked:
            return
        for name in picked:
            if name not in skips:
                skips.append(name)
        if reason not in reasons:
            reasons.append(reason)

    if counts["alive.txt"] == 0:
        add_skips(_ALIVE_MODULES, "alive.txt has 0 lines")
    if counts["urls.txt"] == 0:
        add_skips(_URL_MODULES, "urls.txt has 0 lines")
    elif _in_run("graphql", runnable):
        seen_gql = any(
            _has_token(root / name, "graphql", cap)
            for name, cap in (("alive.txt", 40), ("tech_routes.txt", 40), ("urls.txt", 200))
        )
        if not seen_gql:
            add_skips(("graphql",), "no graphql token in alive, tech_routes, or the url head")

    if skips:
        lines.append("skip_if_chosen: " + " ".join(skips))
        lines.append("why: " + "; ".join(reasons))

    if counts["cname_takeover_candidates.txt"]:
        note = "signal: dangling CNAME already recorded in cname_takeover_candidates.txt. Do not pick dns again."
        if _in_run("takeover_plus", runnable) and "takeover_plus" not in skips:
            note += " takeover_plus outranks another crawl."
        lines.append(note)
    xss_hits = counts["gf_xss.txt"] or counts["xss_reflected_params.txt"]
    if xss_hits and _in_run("xss", runnable) and "xss" not in skips:
        lines.append("signal: xss candidates exist. xss outranks a second crawl.")
    if counts["gf_sqli.txt"] and _in_run("sqli", runnable) and "sqli" not in skips:
        lines.append("signal: sqli candidates exist. sqli outranks a blind content fuzz.")
    if counts["sensitive_paths_found.txt"]:
        lines.append("signal: sensitive_paths_found.txt has hits.")

    heads: list[str] = []
    for name in _HEAD_FILES:
        if not counts.get(name):
            continue
        sample = _head(root / name, 3, 160)
        if sample:
            heads.append(name + ":\n" + "\n".join(sample))
        if len(heads) >= 5:
            break
    if root.is_dir() and len(heads) < 6:
        needles = ("critical", "high", "medium")
        for path in sorted(root.glob("nuclei_*.txt"))[:4]:
            matched = [
                row for row in _head(path, 12, 160)
                if any(needle in row.lower() for needle in needles)
            ][:2]
            if matched:
                heads.append(path.name + ":\n" + "\n".join(matched))
                break
    if heads:
        lines.append("heads:")
        lines.extend(heads)
    return "\n".join(lines) + "\n"


def analyst_evidence(outdir: Path | str, *, max_files: int = 6, per_file: int = 4) -> str:
    """Short heads of high-signal files. Bulk host and URL lists stay as counts."""
    root = Path(outdir)
    if not root.is_dir():
        return "evidence: (no output dir)\n"
    chunks: list[str] = []
    for name in _EVIDENCE_FILES:
        if len(chunks) >= max_files:
            break
        sample = _head(root / name, per_file, 160)
        if sample:
            chunks.append(name + ":\n" + "\n".join(sample))
    if root.is_dir() and len(chunks) < max_files:
        for path in sorted(root.glob("nuclei_*.txt")):
            if len(chunks) >= max_files:
                break
            sample = _head(path, per_file, 160)
            if sample:
                chunks.append(path.name + ":\n" + "\n".join(sample))
    if not chunks:
        return "evidence: (no high-signal heads)\n"
    return "evidence:\n" + "\n".join(chunks) + "\n"
