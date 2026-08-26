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


def run_prompt(
    *,
    prompt: str,
    target: str = "",
    path: str = "",
) -> dict[str, Any]:
    text = (prompt or "").strip()
    if not text:
        return {"ok": False, "error": "prompt required"}
    attached = ""
    meta: dict[str, Any] = {}
    if target and path:
        rec = read_output_file(target, path, max_chars=40_000)
        if rec.get("error"):
            return {"ok": False, "error": rec["error"]}
        attached = rec.get("content") or ""
        meta = {"path": rec.get("path"), "phase": rec.get("phase"), "tool": rec.get("tool")}
    try:
        from agents.llm import LLMClient
        client = LLMClient()
        system = (
            "You are a recon assistant for authorized bug-bounty / VDP work. "
            "Use only the attached reconkit output files. Detection and triage only — "
            "no exploits, shells, dumps, or out-of-scope advice."
        )
        user = text
        if attached:
            user += (
                f"\n\n--- recon file {meta.get('path')} "
                f"(phase={meta.get('phase')} tool={meta.get('tool')}) ---\n"
                f"{attached}"
            )
        reply = client.chat(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            temperature=0.2,
        )
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
