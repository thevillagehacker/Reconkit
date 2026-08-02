"""Persist and load the findings index under ~/.reconkit/."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Prefer reconkit paths when available
try:
    import reconkit as rk

    BASE_DIR = rk.BASE_DIR
    OUTPUT_DIR = rk.OUTPUT_DIR
except Exception:  # pragma: no cover
    BASE_DIR = Path.home() / ".reconkit"
    OUTPUT_DIR = BASE_DIR / "output"

INDEX_DIR = BASE_DIR / "index"
INDEX_FILE = INDEX_DIR / "findings_index.json"


def ensure_index_dir() -> Path:
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    return INDEX_DIR


def save_index(payload: dict[str, Any], path: Path | None = None) -> Path:
    ensure_index_dir()
    path = path or INDEX_FILE
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_index(path: Path | None = None) -> dict[str, Any]:
    path = path or INDEX_FILE
    if not path.exists():
        return {
            "version": "2.2.0",
            "generated_at": "",
            "targets": {},
            "findings": [],
        }
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {
            "version": "2.2.0",
            "generated_at": "",
            "targets": {},
            "findings": [],
            "error": f"failed to parse {path}",
        }
