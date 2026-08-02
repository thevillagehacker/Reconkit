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
    "dns": ["subdomains"],
    "httpprobe": ["subdomains"],
    "tls": ["httpprobe"],
    "crawl": ["httpprobe"],
    "js": ["crawl"],
    "params": ["crawl"],
    "content": ["httpprobe"],
    "xss": ["crawl"],
    "sqli": ["crawl"],
    "ssrf_ssti": ["crawl"],
    "nuclei": ["httpprobe"],
    "cloud": ["crawl"],
    "screenshots": ["httpprobe"],
}

# Key output files each module is expected to produce (for summaries).
MODULE_OUTPUTS: dict[str, list[str]] = {
    "subdomains": ["subdomains.txt"],
    "dns": ["dns_records.txt", "cname_takeover_candidates.txt"],
    "httpprobe": ["alive.txt"],
    "tls": ["tls_recon.json"],
    "crawl": ["urls.txt"],
    "js": ["js_urls.txt", "js_secrets_and_endpoints.json"],
    "params": ["param_names.txt", "arjun_params.txt"],
    "content": ["sensitive_paths_found.txt"],
    "xss": ["xss_reflected_params.txt", "dalfox_results.txt"],
    "sqli": ["sqli_error_based.txt", "sqli_boolean_based.txt"],
    "ssrf_ssti": ["ssrf_metadata_candidates.txt", "ssti_candidates.txt"],
    "nuclei": [],  # nuclei_*.txt — handled dynamically
    "cloud": ["cloud_assets.json", "open_s3_buckets.txt"],
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
