"""
Unified findings layer for reconkit v2.0.1+.

Parses ~/.reconkit/output/<target>/ into structured Finding records that the
dashboard, shell, and (later) scoring/diff/report features all share.
"""

from .history import diff_target, list_snapshots
from .indexer import (
    index_all_targets,
    index_target,
    list_targets,
    output_fingerprint,
)
from .models import Finding, TargetSummary
from .report import build_report_md, write_report
from .scoring import NOTABLE_THRESHOLD, is_notable, score_finding
from .store import load_index, save_index

__all__ = [
    "Finding",
    "TargetSummary",
    "index_all_targets",
    "index_target",
    "list_targets",
    "load_index",
    "save_index",
    "output_fingerprint",
    "diff_target",
    "list_snapshots",
    "write_report",
    "build_report_md",
    "score_finding",
    "is_notable",
    "NOTABLE_THRESHOLD",
]

__version__ = "2.1.0"
