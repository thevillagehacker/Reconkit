"""
Lightweight local tips search (Tier B) — no vector DB.

Keyword search over bug_bounty_tips.md and optional notes for planner/analyst.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
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


def _load_corpus() -> list[tuple[str, str]]:
    """Return list of (source, chunk)."""
    out: list[tuple[str, str]] = []
    if TIPS_FILE.exists():
        try:
            text = TIPS_FILE.read_text(encoding="utf-8", errors="replace")
            for c in _iter_chunks(text):
                out.append((str(TIPS_FILE.name), c))
        except Exception:
            pass
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


def format_context(query: str, limit: int = 4) -> str:
    """String block suitable for injection into an LLM system prompt."""
    hits = search_tips(query, limit=limit)
    if not hits:
        return ""
    parts = ["Local methodology notes (for reference, not orders):"]
    for i, h in enumerate(hits, 1):
        parts.append(f"[{i}] ({h['source']}) {h['text'][:600]}")
    return "\n\n".join(parts)
