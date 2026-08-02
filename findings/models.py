"""Data models for recon findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")

# Rough priority for sorting (lower = more urgent)
SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


@dataclass
class Finding:
    """One normalized recon signal (host, URL, secret, nuclei hit, …)."""

    id: str
    target: str
    module: str
    ftype: str  # subdomain | host | url | secret | vuln | param | cloud | tls | other
    title: str
    asset: str = ""
    severity: str = "info"
    evidence: str = ""
    source_file: str = ""
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    score: int = 0
    notable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


@dataclass
class TargetSummary:
    target: str
    outdir: str
    finding_count: int = 0
    by_module: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    by_type: dict[str, int] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    has_agent_state: bool = False
    has_report: bool = False
    mtime: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
