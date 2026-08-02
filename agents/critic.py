"""
Analyst critic (Tier B) — second-pass review of agent_report.md or draft text.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .llm import LLMClient
from .rag import format_context
from .skills import skill_system_block


CRITIC_SYSTEM = """You are a senior bug bounty reviewer. You do NOT exploit.
Review the recon report draft. Be skeptical of false positives.
Output markdown with sections:
## Likely solid leads
## Possible false positives
## Missing checks
## Suggested next modules
Keep under 600 words. Detection-only advice."""


def review_report(
    report_text: str,
    *,
    llm: LLMClient | None = None,
    target: str = "",
) -> str:
    client = llm or LLMClient()
    tips = format_context(f"{target} recon methodology secrets takeover api", limit=3)
    user = f"Target: {target or '(unknown)'}\n\nREPORT:\n{report_text[:12000]}"
    if tips:
        user = tips + "\n\n" + user
    system = CRITIC_SYSTEM
    skill = skill_system_block(role="analyst", max_chars=5000)
    if skill:
        system = system + "\n\n" + skill
    return client.chat(
        [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.2,
    )


def review_file(path: Path, *, llm: LLMClient | None = None, target: str = "") -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    return review_report(text, llm=llm, target=target or path.parent.name)
