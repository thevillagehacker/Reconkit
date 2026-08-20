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
from .state import ReconState, build_context_bundle
from .tools import module_descriptions, run_modules


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
        "You are Agent 1 — Subdomain Enumeration specialist for authorized bug bounty recon. "
        "Your job is passive/active subdomain discovery for the in-scope root domain only. "
        "You never scan out-of-scope assets. After running, summarize yield and quality."
    ),
    "discovery": (
        "You are the Discovery agent (DNS + HTTP + TLS). You resolve subdomains, probe live "
        "HTTP(S) hosts, and inspect certificates. Prioritize modules that unblock crawl/vuln work."
    ),
    "content": (
        "You are the Content/Surface agent. You crawl live hosts, extract JS secrets/endpoints, "
        "mine parameters, and do light content discovery. Detection only — no exploitation."
    ),
    "vuln": (
        "You are the Vulnerability-candidate agent. You run XSS/SQLi/SSRF/SSTI canaries, nuclei, "
        "and cloud asset checks. Detection and candidates only — never active exploitation tools."
    ),
    "visual": (
        "You are the Visual recon agent. You capture screenshots of live hosts for manual review."
    ),
    "planner": (
        "You are the Recon Orchestrator. Given completed modules and output summaries, decide the "
        "NEXT agent and modules to run. Prefer high-signal next steps. Never recommend out-of-scope "
        "scanning or exploitation. Always stay within the authorized target."
    ),
    "analyst": (
        "You are the Recon Analyst. Summarize findings for a human bug bounty hunter: interesting "
        "hosts, takeover candidates, secrets, vuln candidates. Stay factual; do not invent findings."
    ),
}


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
        ctx = build_context_bundle(state)
        role = AGENT_ROLES.get(self.name, "You are a recon specialist.")
        # On-demand vuln mini-skills from modules + output snippets
        ctx_snip = (ctx or "")[:2500]
        tr_snip = str(tool_results)[:2000]
        mods = modules if modules is not None else list(self.modules)
        skill = skill_system_block(
            role="specialist",
            max_chars=7000,
            context=ctx_snip + "\n" + tr_snip,
            modules=mods,
        )
        if skill:
            role = role + "\n\n" + skill
        user = (
            f"Target: {state.target}\n"
            f"Agent: {self.name}\n"
            f"Tool results:\n{tool_results}\n\n"
            f"Context bundle (file previews):\n{ctx}\n\n"
            "Write a concise 4–8 bullet operational summary for the next agent: "
            "what was found (counts), notable signals, and recommended follow-ups. "
            "Do not invent data not present in the tool results."
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
        descs = module_descriptions()
        ctx = build_context_bundle(state)

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

        skill = skill_system_block(
            role="planner",
            max_chars=9000,
            context=str(ctx)[:3000],
            modules=list(runnable)[:20],
        )
        system = AGENT_ROLES["planner"] + (
            "\n\nRespond ONLY with a JSON object of this shape:\n"
            '{\n'
            '  "done": false,\n'
            '  "next_agent": "discovery" | "content" | "vuln" | "visual" | "subdomain",\n'
            '  "modules": ["httpprobe", "dns"],\n'
            '  "reasoning": "why these next",\n'
            '  "priority": "critical" | "high" | "medium" | "low"\n'
            "}\n"
            "Rules:\n"
            "- modules must be a non-empty subset of RUNNABLE_MODULES (unless done=true).\n"
            "- Prefer: after subdomains → dns+httpprobe; after alive hosts → crawl; "
            "after urls → js/params then vuln modules; nuclei when hosts are alive.\n"
            "- If takeover/secret/vuln signals exist, prioritize related modules.\n"
            "- Set done=true only when remaining work is empty or further scanning is low value.\n"
            "- Never invent modules outside the allowed list.\n"
            "- Batch at most 3 modules per step.\n"
            "- Never recommend exploitation tools or out-of-scope scanning.\n"
        )
        if skill:
            system = system + "\n\n" + skill

        user = (
            f"TARGET: {state.target}\n"
            f"COMPLETED: {state.completed_modules}\n"
            f"REMAINING: {remaining}\n"
            f"RUNNABLE_MODULES (prereqs met): {runnable}\n"
            f"MODULE_DESCRIPTIONS: {descs}\n"
            f"AGENT_MODULES: {AGENT_MODULES}\n"
            f"CONTEXT: {ctx}\n"
        )

        try:
            plan = self.llm.chat_json(
                [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
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
        ctx = build_context_bundle(state, max_files=20)
        system = AGENT_ROLES["analyst"]
        # Surface skills from findings text + completed modules
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
                rows = evaluate_findings(findings, limit=12, use_llm=False)
                eval_block = "\n\nPRE-EVAL (heuristic confidence tiers):\n" + format_eval_report(rows)
                findings_blob = " ".join(
                    f"{f.get('title','')} {f.get('module','')} {f.get('evidence','')[:80]}"
                    for f in findings[:40]
                )
        except Exception:
            pass
        skill = skill_system_block(
            role="analyst",
            max_chars=11000,
            context=(ctx or "")[:2000] + "\n" + findings_blob[:2000],
            modules=list(state.completed_modules or []),
        )
        if skill:
            system = system + "\n\n" + skill
        user = (
            f"Produce a final recon report for target {state.target}.\n"
            f"Completed modules: {state.completed_modules}\n"
            f"Agent history: {state.history}\n"
            f"Context: {ctx}\n"
            f"{eval_block}\n\n"
            "Structure:\n"
            "1. Executive summary\n"
            "2. Asset inventory (subdomains / alive / urls counts if known)\n"
            "3. High-interest findings ONLY if tier C1+ (use PRE-EVAL; drop C0)\n"
            "4. Suggested next steps: /prove techniques from PRE-EVAL next fields, /graph\n"
            "5. Gaps / empty stages\n"
            "Label each finding C0-C4. Candidates ≠ confirmed exploits. No C3 without proof."
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
