"""Scan view snapshot. Run: python tests/test_view.py"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from scan_view import load_snapshot  # noqa: E402


def test_saved_output_counts(tmp: Path) -> None:
    (tmp / "subdomains.txt").write_text("a.example.com\nb.example.com\n", encoding="utf-8")
    (tmp / "alive.txt").write_text("a.example.com\n", encoding="utf-8")
    (tmp / "urls.txt").write_text("", encoding="utf-8")
    (tmp / "run_meta.json").write_text(
        '{"modules": ["subdomains", "dns"]}\n', encoding="utf-8"
    )
    snap = load_snapshot(
        "example.com",
        live={"target": "", "status": "idle", "active": False, "modules": []},
        outdir=tmp,
    )
    assert snap["status"] == "saved"
    assert snap["counts"] == {"subdomains": 2, "alive": 1, "urls": 0}
    assert snap["modules"] == ["subdomains", "dns"]
    assert snap["active"] is False


def test_live_scan_wins_for_the_same_target(tmp: Path) -> None:
    snap = load_snapshot(
        "example.com",
        live={
            "target": "example.com",
            "status": "running",
            "active": True,
            "modules": ["dns"],
            "completed": [],
            "current_module": "dns",
            "current_index": 1,
            "total": 1,
            "current_tool": "dnsx",
            "message": "phase 1/1 · dns",
            "started_at": 0,
            "elapsed_s": 3,
        },
        outdir=tmp,
    )
    assert snap["status"] == "running"
    assert snap["current"] == "dns"
    assert snap["tool"] == "dnsx"
    assert snap["elapsed"] == 3


def main() -> None:
    from tempfile import TemporaryDirectory

    with TemporaryDirectory() as one:
        test_saved_output_counts(Path(one))
    with TemporaryDirectory() as two:
        test_live_scan_wins_for_the_same_target(Path(two))
    print("ok")


if __name__ == "__main__":
    main()
