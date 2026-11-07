"""Data models for safe validation (prove) results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

RiskClass = Literal["safe", "intrusive", "destructive"]
ProofStatus = Literal[
    "queued",
    "running",
    "confirmed",
    "not_exploitable",
    "false_positive",
    "skipped",
    "error",
    "needs_manual",
]


@dataclass
class ProofAttempt:
    """One validation run against a recon finding."""

    id: str
    finding_id: str
    target: str
    technique: str
    risk_class: RiskClass = "safe"
    status: ProofStatus = "queued"
    title: str = ""
    asset: str = ""
    module: str = ""
    evidence: str = ""
    impact_note: str = ""
    source_file: str = ""
    started_at: str = ""
    finished_at: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProofAttempt":
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


# Alias used in docs / CLI
Proof = ProofAttempt
