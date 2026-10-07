"""
Analyst critic (Tier B) — second-pass review of agent_report.md or draft text.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .llm import LLMClient
from .rag import format_context
from .skills import skill_system_block


CRITIC_SYSTEM = (
    "You review one recon report for an authorized target. Detection and triage only. "
    "Use only lines in the report. "
    "Markdown sections, in this order:\n"
    "## Likely solid leads\n"
    "## Possible false positives\n"
    "## Missing checks\n"
    "## Suggested next modules\n"
    "Each section is at most 4 bullets. A lead needs a file name or host from the report. "
    "Suggested modules must be names already used in reconkit. Do not invent tools. "
    "No sqlmap, shells, dumps, or exploit steps. Under 350 words."
)


def review_report(
    report_text: str,
    *,
    llm: LLMClient | None = None,
    target: str = "",
) -> str:
    client = llm or LLMClient()
    tips = format_context(f"{target} recon methodology secrets takeover api", limit=3)
    user = (
        f"target: {target or '(unknown)'}\n"
        "Cite only lines from this report.\n\n"
        f"REPORT:\n{report_text[:8000]}"
    )
    if tips:
        user = tips + "\n\n" + user
    system = CRITIC_SYSTEM
    skill = skill_system_block(
        role="critic",
        max_chars=4000,
        context=report_text[:1500],
    )
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
