"""
Build a force-directed friendly graph from findings index + proofs.

Node kinds: target, host, url, secret, vuln, proof, module_bucket
Edges: has_subdomain, resolves_to, hosts, leaks, indicates, validated_by, same_target
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from findings.store import load_index


def _nid(*parts: str) -> str:
    raw = "|".join(parts)
    return hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:12]


# dnsx/httpx colors become [[35mCNAME[0m] in the UI if left unstripped
_ANSI_RE = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
    r"|\x9B[0-?]*[ -/]*[@-~]"
    r"|\[(?:\d{1,3};){0,8}\d{1,3}m"
)


def _clean_label(text: str) -> str:
    s = _ANSI_RE.sub("", text or "")
    s = s.replace("\x1b", "").replace("\x9b", "")
    s = re.sub(r"[ \t]{2,}", " ", s)
    return s.strip()


def _host_from(text: str) -> str | None:
    text = _clean_label(text or "")
    if not text:
        return None
    if "://" in text:
        try:
            h = urlparse(text).hostname
            return h.lower() if h else None
        except Exception:
            pass
    m = re.search(r"([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})", text)
    return m.group(1).lower().rstrip(".") if m else None


def build_graph(
    *,
    target: str | None = None,
    max_nodes: int = 180,
    max_edges: int = 320,
    include_proofs: bool = True,
    min_score: int = 0,
) -> dict[str, Any]:
    """
    Return {nodes: [...], edges: [...], stats: {...}} for dashboard / API.
    """
    findings: list[dict[str, Any]] = []
    try:
        from findings.indexer import query_store
        findings, _st = query_store(
            target=target, min_score=min_score or None,
            limit=max(max_nodes * 6, 400), offset=0,
        )
    except Exception:
        findings = []
    if not findings:
        idx = load_index()
        findings = list(idx.get("findings") or [])
        if target:
            findings = [f for f in findings if f.get("target") == target]
        findings.sort(key=lambda f: (-int(f.get("score") or 0), f.get("severity") or ""))
        if min_score:
            findings = [f for f in findings if int(f.get("score") or 0) >= min_score]

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    edge_keys: set[str] = set()

    def add_node(nid: str, label: str, kind: str, **meta: Any) -> None:
        if nid in nodes:
            # bump score if higher
            if meta.get("score", 0) > nodes[nid].get("score", 0):
                nodes[nid]["score"] = meta.get("score", 0)
            if meta.get("severity"):
                nodes[nid]["severity"] = meta["severity"]
            return
        if len(nodes) >= max_nodes:
            return
        clean = _clean_label(label)[:80]
        if meta.get("title"):
            meta = {**meta, "title": _clean_label(str(meta["title"]))}
        nodes[nid] = {
            "id": nid,
            "label": clean,
            "kind": kind,
            "score": int(meta.get("score") or 0),
            "severity": meta.get("severity") or "",
            "target": meta.get("target") or "",
            "module": meta.get("module") or "",
            "finding_id": meta.get("finding_id") or "",
            "title": (meta.get("title") or "")[:100],
        }

    def add_edge(src: str, dst: str, rel: str, **meta: Any) -> None:
        if src not in nodes or dst not in nodes:
            return
        if len(edges) >= max_edges:
            return
        key = f"{src}|{rel}|{dst}"
        if key in edge_keys:
            return
        edge_keys.add(key)
        edges.append({
            "id": _nid(key),
            "source": src,
            "target": dst,
            "rel": rel,
            "label": rel.replace("_", " "),
            **{k: v for k, v in meta.items() if v is not None},
        })

    # Limit findings processed to keep graph readable
    for f in findings[: max_nodes * 2]:
        tgt = str(f.get("target") or "unknown")
        tid = _nid("target", tgt)
        add_node(tid, tgt, "target", score=0, target=tgt, title=f"Target {tgt}")

        asset = _clean_label(str(f.get("asset") or ""))
        ftype = str(f.get("ftype") or "other")
        mod = str(f.get("module") or "")
        score = int(f.get("score") or 0)
        sev = str(f.get("severity") or "")
        fid = str(f.get("id") or "")
        title = _clean_label(str(f.get("title") or mod))

        host = _host_from(asset) or _host_from(tgt)
        hid = None
        if host:
            hid = _nid("host", tgt, host)
            add_node(
                hid, host, "host",
                score=score, severity=sev, target=tgt, module=mod,
                finding_id=fid, title=title,
            )
            add_edge(tid, hid, "has_asset")

        # classify node kind for the finding itself
        kind = "finding"
        if ftype == "secret" or mod == "js" and "secret" in title.lower():
            kind = "secret"
        elif ftype == "vuln" or mod in ("nuclei", "xss", "sqli", "ssrf_ssti"):
            kind = "vuln"
        elif ftype == "url" or asset.startswith("http"):
            kind = "url"
        elif ftype in ("subdomain", "host"):
            kind = "host"
        elif "takeover" in title.lower() or (mod == "dns" and "cname" in title.lower()):
            kind = "vuln"

        nid = _nid("f", fid or asset or title)
        label = asset[:50] if asset else title[:50]
        add_node(
            nid, label or title, kind,
            score=score, severity=sev, target=tgt, module=mod,
            finding_id=fid, title=title,
        )
        if hid:
            add_edge(hid, nid, "exposes" if kind in ("vuln", "secret") else "has")
        else:
            add_edge(tid, nid, "has")

        # module bucket hub (light)
        if mod and score >= 40:
            mid = _nid("mod", tgt, mod)
            add_node(mid, f"mod:{mod}", "module", score=0, target=tgt, module=mod)
            add_edge(mid, nid, "from_module")

    # Proofs as validation nodes
    if include_proofs:
        try:
            from prove.store import load_all_proofs

            proofs = load_all_proofs(target)
            for p in proofs[:80]:
                if len(nodes) >= max_nodes:
                    break
                pt = str(p.get("target") or target or "")
                pid = _nid("proof", str(p.get("id") or ""))
                st = str(p.get("status") or "")
                tech = str(p.get("technique") or "")
                add_node(
                    pid,
                    f"proof:{tech}:{st}"[:60],
                    "proof",
                    score=100 if st == "confirmed" else 40,
                    severity="high" if st == "confirmed" else "info",
                    target=pt,
                    module=tech,
                    finding_id=str(p.get("finding_id") or ""),
                    title=str(p.get("title") or tech),
                )
                tid = _nid("target", pt)
                if tid in nodes:
                    add_edge(tid, pid, "validated")
                # link to finding if present
                fid = str(p.get("finding_id") or "")
                if fid:
                    for n in list(nodes.values()):
                        if n.get("finding_id") == fid and n["kind"] != "proof":
                            add_edge(n["id"], pid, "proved_by")
                            break
                # host link
                h = _host_from(str(p.get("asset") or ""))
                if h:
                    hid = _nid("host", pt, h)
                    if hid in nodes:
                        add_edge(hid, pid, "proved_by")
        except Exception:
            pass

    by_kind: dict[str, int] = defaultdict(int)
    for n in nodes.values():
        by_kind[n["kind"]] += 1
    by_rel: dict[str, int] = defaultdict(int)
    for e in edges:
        by_rel[e["rel"]] += 1

    return {
        "version": "2.2.0",
        "target": target or "",
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "by_kind": dict(by_kind),
            "by_rel": dict(by_rel),
            "findings_considered": len(findings),
        },
    }


def graph_summary(g: dict[str, Any]) -> str:
    st = g.get("stats") or {}
    lines = [
        f"nodes: {st.get('node_count', 0)}  edges: {st.get('edge_count', 0)}",
        f"by kind: {st.get('by_kind') or {}}",
        f"by rel:  {st.get('by_rel') or {}}",
    ]
    return "\n".join(lines)
