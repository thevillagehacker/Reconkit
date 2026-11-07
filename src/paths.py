"""Locations that stay at the repo root while the code lives in src/."""

from pathlib import Path

SRC = Path(__file__).resolve().parent
REPO_ROOT = SRC.parent
