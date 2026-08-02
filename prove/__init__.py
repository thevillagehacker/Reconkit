"""
Safe validation / prove layer (v3.0.0).

Detection candidates from recon → queue → non-destructive validators → Proof records.
Never installs or runs active exploit frameworks (sqlmap, shells, dumps).
"""

from __future__ import annotations

__version__ = "3.0.0"

from .models import Proof, ProofAttempt, RiskClass
from .queue import build_queue, queue_summary
from .runner import run_proofs, run_one
from .policy import load_policy, policy_summary

__all__ = [
    "Proof",
    "ProofAttempt",
    "RiskClass",
    "build_queue",
    "queue_summary",
    "run_proofs",
    "run_one",
    "load_policy",
    "policy_summary",
    "__version__",
]
