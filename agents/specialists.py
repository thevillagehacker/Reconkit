"""
Specialist recon agents.

Each agent owns a slice of the pipeline, can run its modules via tools,
and returns a structured summary the planner uses to decide what comes next.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .llm import LLMClient
from .skills import skill_system_block
from .state import ReconState, analyst_evidence, recon_brief
from .tools import run_modules


@dataclass
class AgentResult:
    agent: str
    modules_run: list[str]
    reasoning: str
    summary: str
    success: bool
    details: dict[str, Any]


# Agent → modules it is allowed / expected to execute
AGENT_MODULES: dict[str, list[str]] = {
    "subdomain": ["subdomains", "permute"],
    "discovery": ["dns", "ports", "httpprobe", "tls", "wellknown", "osint"],
    "content": ["crawl", "js", "jsintel", "params", "apis", "content", "bypass403", "gfextra"],
    "vuln": [
        "xss", "sqli", "ssrf_ssti", "redirect", "cors", "graphql",
        "nuclei", "cloud", "takeover_plus", "gitrecon",
    ],
    "visual": ["screenshots"],
}

AGENT_ROLES: dict[str, str] = {
    "subdomain": (
        "You summarize subdomain enumeration for one authorized root. "
        "Counts and names come from the tool files only."
    ),
    "discovery": (
        "You summarize DNS and live HTTP for one authorized target. "
        "A name with no DNS record is not a live host."
    ),
    "content": (
        "You summarize crawled URLs, JavaScript, and parameters for one authorized target. "
        "Detection only."
    ),
    "vuln": (
        "You summarize scanner candidates for one authorized target. "
        "A candidate is not a confirmed issue. No exploit steps."
    ),
    "visual": (
        "You summarize which live hosts were screenshotted."
    ),
    "planner": (
        "You choose the next recon modules for one authorized target from the file counts."
    ),
    "analyst": (
        "You write a short recon report from file counts and heads. You do not invent findings."
    ),
}

_PLANNER_RULES = (
    "Reply with one JSON object and nothing else:\n"
    '{"done":false,"next_agent":"discovery","modules":["dns","httpprobe"],'
    '"reasoning":"at most 40 words","priority":"high"}\n'
    "next_agent is one of: subdomain, discovery, content, vuln, visual.\n"
    "modules is 1 to 3 names from runnable, all owned by next_agent.\n"
    "priority is critical, high, medium, or low.\n"
    "File counts and heads outrank the default pipeline in the skill text.\n"
    "Obey skip_if_chosen. Unresolved permute names are not hosts.\n"
    "Prefer the runnable module that reads a non-empty file the completed modules have not used.\n"
    "A non-empty cname_takeover_candidates.txt is already a finding: do not pick dns again.\n"
    "Set done to true when runnable is empty, or when every runnable module is listed in skip_if_chosen.\n"
    "Do not invent modules, start /prove, widen scope, or mention sqlmap, shells, or dumps."
)


def tool_result_lines(tool_results: list[dict]) -> str:
    """Module, file, and line count. Previews stay out of the prompt."""
    rows: list[str] = []
    for result in tool_results:
        mod = str(result.get("module") or "?")
        if result.get("skipped"):
            rows.append(f"{mod}: skipped")
            continue
        if result.get("success") is False:
            err = str(result.get("error") or "failed")[:140]
            rows.append(f"{mod}: failed {err}")
            continue
        bits: list[str] = []
        for item in result.get("outputs") or []:
            path = str(item.get("path") or "?")
            if not item.get("exists"):
                bits.append(f"{path}=missing")
                continue
            if item.get("empty"):
                bits.append(f"{path}=0")
                continue
            bits.append(f"{path}={item.get('lines', 0)}")
            keys = item.get("interesting_keywords") or []
            if keys:
                bits.append(f"{path} keys={','.join(str(key) for key in keys[:4])}")
        rows.append(f"{mod}: " + (", ".join(bits) if bits else "no files"))
    return "\n".join(rows)


def planner_user(state: ReconState, runnable: list[str], brief: str | None = None) -> str:
    owners = "; ".join(
        f"{agent}={','.join(mods)}" for agent, mods in AGENT_MODULES.items()
    )
    if brief is None:
        brief = recon_brief(state.outdir, runnable)
    return (
        f"target: {state.target}\n"
        f"completed: {', '.join(state.completed_modules) or '-'}\n"
        f"runnable: {', '.join(runnable) or '-'}\n"
        f"owners: {owners}\n"
        f"{brief}"
        "Choose from runnable. Obey skip_if_chosen.\n"
    )


def planner_messages(state: ReconState, runnable: list[str]) -> list[dict[str, str]]:
    brief = recon_brief(state.outdir, runnable)
    skill = skill_system_block(
        role="planner",
        max_chars=6500,
        context=brief[:2500],
        modules=list(runnable)[:12],
    )
    system = AGENT_ROLES["planner"] + "\n\n" + _PLANNER_RULES
    if skill:
        system = system + "\n\n" + skill
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": planner_user(state, runnable, brief)},
    ]


class SpecialistAgent:
    """Runs a fixed set of recon modules, then asks the LLM for a short summary."""

    name: str
    modules: list[str]

    def __init__(self, name: str, llm: LLMClient):
        if name not in AGENT_MODULES and name not in ("planner", "analyst"):
            raise ValueError(f"Unknown agent: {name}")
        self.name = name
        self.llm = llm
        self.modules = list(AGENT_MODULES.get(name, []))

    def run(
        self,
        state: ReconState,
        *,
        modules: list[str] | None = None,
        force: bool = False,
    ) -> AgentResult:
        target = state.target
        outdir = Path(state.outdir)
        to_run = modules if modules is not None else self.modules

        # Only run modules this agent owns (planner may pass a subset)
        owned = set(self.modules)
        to_run = [m for m in to_run if m in owned] if owned else to_run
        if not force:
            to_run = [m for m in to_run if m not in state.completed_modules]

        if not to_run:
            return AgentResult(
                agent=self.name,
                modules_run=[],
                reasoning="No pending modules for this agent.",
                summary="Nothing to run — modules already complete or empty selection.",
                success=True,
                details={},
            )

        tool_results = run_modules(to_run, target, outdir, state)
        ok = all(r.get("success") or r.get("skipped") for r in tool_results)
        ran = [r["module"] for r in tool_results if r.get("success") and not r.get("skipped")]

        summary = self._llm_summarize(state, tool_results, modules=to_run)
        return AgentResult(
            agent=self.name,
            modules_run=ran,
            reasoning=f"Executed modules: {', '.join(to_run) or '(none)'}",
            summary=summary,
            success=ok,
            details={"tool_results": tool_results},
        )

    def _llm_summarize(
        self,
        state: ReconState,
        tool_results: list[dict],
        *,
        modules: list[str] | None = None,
    ) -> str:
        brief = recon_brief(state.outdir)
        ran = tool_result_lines(tool_results)
        role = AGENT_ROLES.get(self.name, "You summarize one authorized recon step from the files.")
        mods = modules if modules is not None else list(self.modules)
        skill = skill_system_block(
            role="specialist",
            max_chars=7000,
            context=(brief + "\n" + ran)[:2500],
            modules=mods,
        )
        if skill:
            role = role + "\n\n" + skill
        user = (
            f"target: {state.target}\n"
            f"agent: {self.name}\n"
            f"just_ran:\n{ran}\n\n"
            f"{brief}"
            "Write 4 to 6 bullets. Each bullet is one count or one name copied from just_ran or heads. "
            "End with one line: next: <module> because <file count>. "
            "Use next: none when the files are empty. "
            "Do not invent hosts, secrets, or issues."
        )
        try:
            return self.llm.chat(
                [
                    {"role": "system", "content": role},
                    {"role": "user", "content": user},
                ],
                temperature=0.2,
            ).strip()
        except Exception as e:
            # LLM optional for execution path — always return a deterministic fallback
            highlights = []
            for r in tool_results:
                for h in (r.get("outputs") or []):
                    if h.get("lines"):
                        highlights.append(f"{h.get('path')}: {h.get('lines')} lines")
            return (
                f"[LLM unavailable: {e}] "
                f"Modules done. Highlights: {'; '.join(highlights) or 'n/a'}"
            )


class PlannerAgent:
    """
    Decides the next agent + modules from current state.
    Returns structured JSON plan.
    """

    def __init__(self, llm: LLMClient):
        self.llm = llm
        self.name = "planner"

    def plan(self, state: ReconState, all_modules: list[str]) -> dict[str, Any]:
        runnable = state.runnable_modules(all_modules)
        remaining = state.remaining_modules(all_modules)

        # Deterministic bootstrap: always start with subdomains if not done
        if "subdomains" not in state.completed_modules and "subdomains" in all_modules:
            return {
                "done": False,
                "next_agent": "subdomain",
                "modules": ["subdomains"],
                "reasoning": "Bootstrap: Agent 1 must enumerate subdomains before any downstream work.",
                "priority": "critical",
            }

        # If nothing left, finish without LLM
        if not remaining:
            return {
                "done": True,
                "next_agent": None,
                "modules": [],
                "reasoning": "All modules completed.",
                "priority": "none",
            }

        try:
            plan = self.llm.chat_json(
                planner_messages(state, runnable),
                temperature=0.1,
            )
        except Exception as e:
            plan = self._heuristic_plan(state, runnable, remaining)
            plan["reasoning"] = f"[LLM fallback: {e}] " + plan.get("reasoning", "")
            return plan

        return self._validate_plan(plan, runnable, remaining)

    def _validate_plan(
        self,
        plan: dict[str, Any],
        runnable: list[str],
        remaining: list[str],
    ) -> dict[str, Any]:
        done = bool(plan.get("done"))
        modules = plan.get("modules") or []
        if not isinstance(modules, list):
            modules = []
        modules = [m for m in modules if m in runnable]

        agent = plan.get("next_agent")
        if agent not in AGENT_MODULES and not done:
            agent = self._agent_for_modules(modules) if modules else None

        # If model returned invalid modules, fall back to heuristics
        if not done and not modules:
            return self._heuristic_from_lists(runnable, remaining, plan)

        # Clip modules to those owned by chosen agent if agent set
        if agent and agent in AGENT_MODULES and modules:
            owned = set(AGENT_MODULES[agent])
            clipped = [m for m in modules if m in owned]
            if clipped:
                modules = clipped
            else:
                agent = self._agent_for_modules(modules)

        return {
            "done": done,
            "next_agent": None if done else agent,
            "modules": [] if done else modules,
            "reasoning": str(plan.get("reasoning") or ""),
            "priority": str(plan.get("priority") or "medium"),
        }

    def _heuristic_from_lists(
        self,
        runnable: list[str],
        remaining: list[str],
        prior: dict | None = None,
    ) -> dict[str, Any]:
        if not remaining:
            return {
                "done": True,
                "next_agent": None,
                "modules": [],
                "reasoning": "All modules completed.",
                "priority": "none",
            }
        if not runnable:
            return {
                "done": True,
                "next_agent": None,
                "modules": [],
                "reasoning": "No runnable modules (blocked on prerequisites).",
                "priority": "none",
            }

        # Preferred order of batches
        batches = [
            ("subdomain", ["subdomains"]),
            ("discovery", ["dns", "httpprobe"]),
            ("discovery", ["tls"]),
            ("content", ["crawl"]),
            ("content", ["js", "params", "content"]),
            ("vuln", ["nuclei", "xss", "sqli", "ssrf_ssti", "cloud"]),
            ("visual", ["screenshots"]),
        ]
        for agent, mods in batches:
            pick = [m for m in mods if m in runnable]
            if pick:
                return {
                    "done": False,
                    "next_agent": agent,
                    "modules": pick,
                    "reasoning": (prior or {}).get("reasoning")
                    or f"Heuristic next batch: {agent} → {pick}",
                    "priority": "high" if agent in ("subdomain", "discovery") else "medium",
                }
        # any remaining runnable
        m = runnable[0]
        return {
            "done": False,
            "next_agent": self._agent_for_modules([m]),
            "modules": [m],
            "reasoning": f"Heuristic single-module step: {m}",
            "priority": "low",
        }

    def _heuristic_plan(
        self,
        state: ReconState,
        runnable: list[str],
        remaining: list[str],
    ) -> dict[str, Any]:
        return self._heuristic_from_lists(runnable, remaining)

    @staticmethod
    def _agent_for_modules(modules: list[str]) -> str | None:
        if not modules:
            return None
        scores: dict[str, int] = {}
        for agent, owned in AGENT_MODULES.items():
            scores[agent] = sum(1 for m in modules if m in owned)
        best = max(scores, key=scores.get)  # type: ignore
        return best if scores[best] > 0 else None


class AnalystAgent:
    def __init__(self, llm: LLMClient):
        self.llm = llm
        self.name = "analyst"

    def report(self, state: ReconState) -> str:
        brief = recon_brief(state.outdir)
        evidence = analyst_evidence(state.outdir)
        system = AGENT_ROLES["analyst"]
        findings_blob = ""
        eval_block = ""
        try:
            from findings.store import load_index
            from .eval import evaluate_findings, format_eval_report

            findings = [
                f for f in (load_index().get("findings") or [])
                if f.get("target") == state.target
            ]
            if findings:
                rows = evaluate_findings(findings, limit=8, use_llm=False)
                eval_block = "\nPRE-EVAL:\n" + format_eval_report(rows)
                findings_blob = " ".join(
                    f"{f.get('title','')} {f.get('module','')}"
                    for f in findings[:12]
                )
        except Exception:
            pass
        skill = skill_system_block(
            role="analyst",
            max_chars=7000,
            context=(brief + "\n" + evidence + "\n" + findings_blob)[:2500],
            modules=list(state.completed_modules or [])[:12],
        )
        if skill:
            system = system + "\n\n" + skill
        user = (
            f"target: {state.target}\n"
            f"completed: {', '.join(state.completed_modules) or '-'}\n"
            f"{brief}{evidence}{eval_block}\n"
            "Write five short sections: Summary, Inventory, Leads, Next, Gaps.\n"
            "Inventory repeats the counts above.\n"
            "A lead needs a host or URL copied from evidence or PRE-EVAL. Tag C0-C4. "
            "C2 needs a canary or proof already in that text. No C3.\n"
            "Next names one /prove technique id from PRE-EVAL, or none. Do not claim it ran.\n"
            "Gaps names empty files that block a check."
        )
        try:
            return self.llm.chat(
                [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=0.2,
            ).strip()
        except Exception as e:
            return (
                f"# Recon report (LLM unavailable: {e})\n\n"
                f"Target: {state.target}\n"
                f"Completed: {', '.join(state.completed_modules)}\n"
                f"Output dir: {state.outdir}\n"
                f"Steps: {len(state.history)}\n"
            )
