"""
Keyword search over the skill files in skills/ and optional local notes.

No vector DB. /tips uses this. Model calls load skill files directly.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from paths import REPO_ROOT as _ROOT

SKILLS_DIR = _ROOT / "skills"
TIPS_FILE = _ROOT / "bug_bounty_tips.md"
NOTES_DIR = Path.home() / ".reconkit" / "notes"


def _iter_chunks(text: str, size: int = 800) -> list[str]:
    paras = re.split(r"\n{2,}", text)
    chunks: list[str] = []
    buf = ""
    for p in paras:
        p = p.strip()
        if not p:
            continue
        if len(buf) + len(p) < size:
            buf = (buf + "\n\n" + p).strip()
        else:
            if buf:
                chunks.append(buf)
            buf = p
    if buf:
        chunks.append(buf)
    return chunks


def _add_file(out: list[tuple[str, str]], path: Path, source: str) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for chunk in _iter_chunks(text):
        out.append((source, chunk))


def _load_corpus() -> list[tuple[str, str]]:
    """Return list of (source, chunk). Skill files are the methodology."""
    out: list[tuple[str, str]] = []
    if SKILLS_DIR.is_dir():
        for path in sorted(SKILLS_DIR.rglob("*.md")):
            if path.name == "README.md":
                continue
            try:
                source = str(path.relative_to(_ROOT)).replace("\\", "/")
            except ValueError:
                source = path.name
            _add_file(out, path, source)
    if TIPS_FILE.is_file():
        _add_file(out, TIPS_FILE, TIPS_FILE.name)
    if NOTES_DIR.exists():
        for p in NOTES_DIR.glob("**/*"):
            if p.is_file() and p.suffix.lower() in (".md", ".txt"):
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                    for c in _iter_chunks(text):
                        out.append((str(p), c))
                except Exception:
                    pass
    return out


def search_tips(query: str, limit: int = 5) -> list[dict[str, Any]]:
    """Score chunks by simple term overlap."""
    q = (query or "").strip().lower()
    if not q:
        return []
    terms = [t for t in re.split(r"\W+", q) if len(t) > 2]
    if not terms:
        terms = [q]
    hits: list[tuple[int, str, str]] = []
    for src, chunk in _load_corpus():
        low = chunk.lower()
        score = sum(3 if t in low else 0 for t in terms)
        # bonus if phrase appears
        if q in low:
            score += 10
        if score:
            hits.append((score, src, chunk))
    hits.sort(key=lambda x: -x[0])
    return [
        {"score": s, "source": src, "text": chunk[:1200]}
        for s, src, chunk in hits[:limit]
    ]


