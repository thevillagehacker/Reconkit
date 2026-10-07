"""Dashboard LLM prompt — uses the same agent config as the CLI."""

from __future__ import annotations

from typing import Any

from dashboard.outputs import read_output_file


def llm_status() -> dict[str, Any]:
    try:
        from agents.llm import LLMClient
        from agents.config import load_config
        cfg = load_config()
        client = LLMClient(cfg)
        c = client.config
        return {
            "ok": True,
            "provider": c.provider,
            "model": c.model,
            "base_url": c.base_url,
            "openai_compat": bool(getattr(c, "use_openai_compat", False)),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "provider": "", "model": ""}


def _phase_bundle(target: str, phase: str, budget: int = 40_000, per_file: int = 6_000) -> tuple[str, dict[str, Any]]:
    """Head of each small file in one phase. Tool files first, then merges."""
    from dashboard.outputs import list_output_files

    listing = list_output_files(target)
    if listing.get("error"):
        return "", {"error": listing["error"]}
    files = []
    for f in listing.get("files") or []:
        if f.get("phase") != phase:
            continue
        name = str(f.get("name") or "")
        if name == "dropped.txt" or name.endswith(".prev") or f.get("kind") == "binary":
            continue
        if int(f.get("size") or 0) > 5_000_000:
            continue
        files.append(f)
    files.sort(key=lambda f: (0 if f.get("kind") == "tool" else 1, int(f.get("size") or 0)))
    parts: list[str] = []
    metas: list[dict[str, Any]] = []
    used = 0
    for f in files:
        if len(metas) >= 8 or used >= budget:
            break
        rec = read_output_file(target, str(f.get("path") or ""), max_chars=per_file)
        content = rec.get("content") or ""
        if not str(content).strip():
            continue
        parts.append(
            f"\n\n--- {f.get('path')} phase={f.get('phase')} tool={f.get('tool')} ---\n{content}"
        )
        used += len(content)
        metas.append({
            "path": f.get("path"),
            "truncated": bool(rec.get("truncated") or rec.get("too_large")),
        })
    if not parts:
        return "", {"error": f"no readable files in phase {phase}"}
    return "".join(parts), {"phase": phase, "files": metas, "truncated": used >= budget or len(files) > len(metas)}


def _attach(target: str, path: str, phase: str) -> tuple[str, dict[str, Any], str]:
    """Return (attached text, meta, error). error is empty on success."""
    if target and phase:
        attached, meta = _phase_bundle(target, phase)
        if meta.get("error"):
            return "", meta, str(meta["error"])
        return attached, meta, ""
    if target and path:
        rec = read_output_file(target, path, max_chars=40_000)
        # too_large still returns a head of the file — do not fail the prompt.
        if rec.get("error") and not rec.get("too_large") and not rec.get("content"):
            return "", {}, str(rec["error"])
        meta = {
            "path": rec.get("path"),
            "phase": rec.get("phase"),
            "tool": rec.get("tool"),
            "truncated": bool(rec.get("truncated") or rec.get("too_large")),
        }
        return rec.get("content") or "", meta, ""
    return "", {}, ""


def _messages(prompt: str, attached: str, meta: dict[str, Any]) -> list[dict[str, str]]:
    system = (
        "You answer from the attached reconkit output for one authorized target. "
        "Quote counts and hosts that appear in the attachment. "
        "If the attachment does not contain the answer, say it is not in the file. "
        "Detection and triage only. Do not give exploit steps, shells, dumps, "
        "sqlmap usage, or out-of-scope targets. Do not start a scan. "
        "When asked what to do next, name one module the files already support, or none."
    )
    user = prompt
    if attached:
        if meta.get("phase") and meta.get("files"):
            user += f"\n\n--- recon phase {meta.get('phase')} ---{attached}"
        else:
            user += (
                f"\n\n--- recon file {meta.get('path')} "
                f"(phase={meta.get('phase')} tool={meta.get('tool')}) ---\n"
                f"{attached}"
            )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def _visible_deltas(chunks):
    """Drop a leading <think> block that some local models emit."""
    pending = ""
    skipping = False
    for chunk in chunks:
        if not chunk:
            continue
        pending += chunk
        while pending:
            if skipping:
                end = pending.find("</think>")
                if end < 0:
                    pending = pending[-16:]
                    break
                pending = pending[end + len("</think>"):]
                skipping = False
                continue
            start = pending.find("<think>")
            if start < 0:
                hold = 8 if "<" in pending[-8:] else 0
                emit = pending[:-hold] if hold else pending
                pending = pending[-hold:] if hold else ""
                if emit:
                    yield emit
                break
            if start > 0:
                yield pending[:start]
            pending = pending[start + len("<think>"):]
            skipping = True
    if pending and not skipping:
        yield pending


def run_prompt(
    *,
    prompt: str,
    target: str = "",
    path: str = "",
    phase: str = "",
) -> dict[str, Any]:
    text = (prompt or "").strip()
    if not text:
        return {"ok": False, "error": "prompt required"}
    attached, meta, err = _attach(target, path, phase)
    if err:
        return {"ok": False, "error": err}
    try:
        from agents.llm import LLMClient
        client = LLMClient()
        reply = client.chat(_messages(text, attached, meta), temperature=0.2)
        st = llm_status()
        return {
            "ok": True,
            "reply": reply,
            "provider": st.get("provider"),
            "model": st.get("model"),
            "attached": meta,
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def iter_prompt_events(*, prompt: str, target: str = "", path: str = "", phase: str = ""):
    """Yield SSE-sized dicts: meta, delta, done, or error."""
    text = (prompt or "").strip()
    if not text:
        yield {"error": "prompt required"}
        return
    attached, meta, err = _attach(target, path, phase)
    if err:
        yield {"error": err}
        return
    try:
        from agents.llm import LLMClient
        client = LLMClient()
        st = llm_status()
        yield {
            "meta": {
                "provider": st.get("provider"),
                "model": st.get("model"),
                "attached": meta,
            }
        }
        for delta in _visible_deltas(client.chat_stream(_messages(text, attached, meta), temperature=0.2)):
            if delta:
                yield {"delta": delta}
        yield {"done": True, "provider": st.get("provider"), "model": st.get("model")}
    except Exception as e:
        yield {"error": f"{type(e).__name__}: {e}"}
