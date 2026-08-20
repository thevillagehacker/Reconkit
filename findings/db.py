"""SQLite findings index for large scan corpora.

JSON (`findings_index.json`) remains a compatibility cache. SQLite is the
queryable store used when the dashboard filters or the corpus is large.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from .store import BASE_DIR

DB_PATH = BASE_DIR / "index" / "findings.sqlite"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT
);
CREATE TABLE IF NOT EXISTS targets (
  target TEXT PRIMARY KEY,
  outdir TEXT,
  finding_count INTEGER,
  payload TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  target TEXT,
  module TEXT,
  ftype TEXT,
  title TEXT,
  asset TEXT,
  severity TEXT,
  evidence TEXT,
  source_file TEXT,
  tags TEXT,
  score INTEGER,
  notable INTEGER,
  confidence TEXT,
  status TEXT,
  generated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_f_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_f_module ON findings(module);
CREATE INDEX IF NOT EXISTS idx_f_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_f_conf ON findings(confidence);
CREATE INDEX IF NOT EXISTS idx_f_score ON findings(score);
CREATE INDEX IF NOT EXISTS idx_f_status ON findings(status);
"""


def db_path() -> Path:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return DB_PATH


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path()))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def replace_index(payload: dict[str, Any]) -> Path:
    """Replace the whole index from an indexer payload."""
    generated = str(payload.get("generated_at") or "")
    fp = str(payload.get("output_fingerprint") or "")
    findings = list(payload.get("findings") or payload.get("records") or [])
    targets = payload.get("targets") or {}
    conn = connect()
    try:
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM targets")
        conn.execute("DELETE FROM meta")
        conn.execute("INSERT INTO meta(k, v) VALUES(?, ?)", ("generated_at", generated))
        conn.execute("INSERT INTO meta(k, v) VALUES(?, ?)", ("output_fingerprint", fp))
        conn.execute(
            "INSERT INTO meta(k, v) VALUES(?, ?)",
            ("finding_count", str(payload.get("finding_count") or len(findings))),
        )
        rows = []
        for d in findings:
            rows.append((
                str(d.get("id") or ""),
                str(d.get("target") or ""),
                str(d.get("module") or ""),
                str(d.get("ftype") or ""),
                str(d.get("title") or "")[:500],
                str(d.get("asset") or "")[:500],
                str(d.get("severity") or "info"),
                str(d.get("evidence") or "")[:4000],
                str(d.get("source_file") or ""),
                json.dumps(d.get("tags") or []),
                int(d.get("score") or 0),
                1 if d.get("notable") else 0,
                str(d.get("confidence") or "C0"),
                str(d.get("status") or "inventory"),
                generated,
            ))
        conn.executemany(
            """INSERT OR REPLACE INTO findings
               (id, target, module, ftype, title, asset, severity, evidence,
                source_file, tags, score, notable, confidence, status, generated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        for name, info in (targets or {}).items():
            conn.execute(
                "INSERT OR REPLACE INTO targets(target, outdir, finding_count, payload) VALUES(?,?,?,?)",
                (
                    name,
                    str((info or {}).get("outdir") or ""),
                    int((info or {}).get("finding_count") or 0),
                    json.dumps(info or {}),
                ),
            )
        conn.commit()
    finally:
        conn.close()
    return DB_PATH


def meta() -> dict[str, str]:
    if not DB_PATH.exists():
        return {}
    conn = connect()
    try:
        return {str(r["k"]): str(r["v"] or "") for r in conn.execute("SELECT k, v FROM meta")}
    finally:
        conn.close()


def usable(live_fingerprint: str | None = None) -> bool:
    """True when SQLite exists, has rows, and (optionally) matches output fingerprint."""
    if not DB_PATH.exists():
        return False
    m = meta()
    conn = connect()
    try:
        n = int(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0])
    finally:
        conn.close()
    if n <= 0:
        return False
    if live_fingerprint:
        return str(m.get("output_fingerprint") or "") == str(live_fingerprint)
    return True


def load_targets() -> dict[str, Any]:
    if not DB_PATH.exists():
        return {}
    conn = connect()
    try:
        out: dict[str, Any] = {}
        for r in conn.execute("SELECT target, outdir, finding_count, payload FROM targets"):
            try:
                payload = json.loads(r["payload"] or "{}")
            except Exception:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            payload.setdefault("target", r["target"])
            payload.setdefault("outdir", r["outdir"])
            payload.setdefault("finding_count", r["finding_count"])
            out[str(r["target"])] = payload
        return out
    finally:
        conn.close()


def slim_payload() -> dict[str, Any]:
    """Index header without embedding every finding (dashboard / large corpora)."""
    m = meta()
    try:
        n = int(m.get("finding_count") or 0)
    except (TypeError, ValueError):
        n = 0
    return {
        "version": "3.0.0",
        "generated_at": m.get("generated_at") or "",
        "finding_count": n,
        "record_count": n,
        "targets": load_targets(),
        "findings": [],
        "records": [],
        "output_fingerprint": m.get("output_fingerprint") or "",
        "backend": "sqlite",
    }


def _where(
    *,
    target: str | None = None,
    module: str | None = None,
    severity: str | None = None,
    ftype: str | None = None,
    q: str | None = None,
    notable: bool | None = None,
    min_score: int | None = None,
    confidence: str | None = None,
    min_confidence: str | None = None,
    status: str | None = None,
) -> tuple[str, list[Any]]:
    where: list[str] = []
    args: list[Any] = []
    if target:
        where.append("target = ?")
        args.append(target)
    if module:
        where.append("module = ?")
        args.append(module)
    if severity:
        where.append("LOWER(severity) = LOWER(?)")
        args.append(severity)
    if ftype:
        where.append("ftype = ?")
        args.append(ftype)
    if notable is True:
        where.append("notable = 1")
    if min_score is not None:
        where.append("score >= ?")
        args.append(int(min_score))
    if confidence:
        where.append("UPPER(confidence) = ?")
        args.append(confidence.upper())
    if min_confidence:
        order = {"C0": 0, "C1": 1, "C2": 2, "C3": 3, "C4": 4}
        min_n = order.get(min_confidence.upper(), 0)
        allowed = [k for k, v in order.items() if v >= min_n]
        where.append("UPPER(confidence) IN (%s)" % ",".join("?" * len(allowed)))
        args.extend(allowed)
    if status:
        where.append("status = ?")
        args.append(status)
    if q:
        like = f"%{q}%"
        where.append(
            "(title LIKE ? OR asset LIKE ? OR evidence LIKE ? OR module LIKE ? OR target LIKE ?)"
        )
        args.extend([like, like, like, like, like])
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    return clause, args


def query_findings(
    *,
    target: str | None = None,
    module: str | None = None,
    severity: str | None = None,
    ftype: str | None = None,
    q: str | None = None,
    notable: bool | None = None,
    min_score: int | None = None,
    confidence: str | None = None,
    min_confidence: str | None = None,
    status: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Return (rows, total_matching)."""
    if not DB_PATH.exists():
        return [], 0
    clause, args = _where(
        target=target, module=module, severity=severity, ftype=ftype, q=q,
        notable=notable, min_score=min_score, confidence=confidence,
        min_confidence=min_confidence, status=status,
    )
    conn = connect()
    try:
        total = conn.execute(f"SELECT COUNT(*) FROM findings {clause}", args).fetchone()[0]
        limit = max(0, min(int(limit), 5000))
        offset = max(0, int(offset))
        rows = conn.execute(
            f"""SELECT * FROM findings {clause}
                ORDER BY notable DESC, score DESC, severity ASC
                LIMIT ? OFFSET ?""",
            [*args, limit, offset],
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["tags"] = json.loads(d.get("tags") or "[]")
            except Exception:
                d["tags"] = []
            d["notable"] = bool(d.get("notable"))
            out.append(d)
        return out, int(total)
    finally:
        conn.close()


def query_stats(
    *,
    target: str | None = None,
    module: str | None = None,
    severity: str | None = None,
    ftype: str | None = None,
    q: str | None = None,
    notable: bool | None = None,
    min_score: int | None = None,
    confidence: str | None = None,
    min_confidence: str | None = None,
    status: str | None = None,
) -> dict[str, Any]:
    empty: dict[str, Any] = {
        "total": 0,
        "notable_count": 0,
        "by_severity": {},
        "by_module": {},
        "by_type": {},
        "by_confidence": {},
    }
    if not DB_PATH.exists():
        return empty
    clause, args = _where(
        target=target, module=module, severity=severity, ftype=ftype, q=q,
        notable=notable, min_score=min_score, confidence=confidence,
        min_confidence=min_confidence, status=status,
    )
    conn = connect()
    try:
        total = int(conn.execute(f"SELECT COUNT(*) FROM findings {clause}", args).fetchone()[0])
        extra = " AND notable = 1" if clause else "WHERE notable = 1"
        notable_n = int(conn.execute(
            f"SELECT COUNT(*) FROM findings {clause}{extra}", args
        ).fetchone()[0])
        by_sev = {
            str(r[0] or "unknown"): int(r[1])
            for r in conn.execute(
                f"SELECT severity, COUNT(*) FROM findings {clause} GROUP BY severity", args
            )
        }
        by_mod = {
            str(r[0] or "other"): int(r[1])
            for r in conn.execute(
                f"SELECT module, COUNT(*) FROM findings {clause} GROUP BY module", args
            )
        }
        by_type = {
            str(r[0] or "other"): int(r[1])
            for r in conn.execute(
                f"SELECT ftype, COUNT(*) FROM findings {clause} GROUP BY ftype", args
            )
        }
        by_conf = {
            str(r[0] or "C0"): int(r[1])
            for r in conn.execute(
                f"SELECT confidence, COUNT(*) FROM findings {clause} GROUP BY confidence", args
            )
        }
        return {
            "total": total,
            "notable_count": notable_n,
            "by_severity": by_sev,
            "by_module": by_mod,
            "by_type": by_type,
            "by_confidence": by_conf,
        }
    finally:
        conn.close()
