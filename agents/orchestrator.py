"""
Multi-agent recon orchestrator.

Flow:
  1. Scope gate (via reconkit)
  2. Planner decides next agent + modules (LLM + heuristics)
  3. Specialist agent runs modules through reconkit stages
  4. Results feed back into shared state
  5. Repeat until planner says done or max_steps hit
  6. Analyst produces a final report
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .llm import LLMClient, LLMConfig
from .specialists import AGENT_MODULES, AnalystAgent, PlannerAgent, SpecialistAgent
from .state import AgentStep, ReconState
from .tools import list_modules, prepare_outdir, require_scope


class ReconOrchestrator:
    def __init__(
        self,
        target: str,
        llm: LLMClient | None = None,
        *,
        max_steps: int = 12,
        modules_allowlist: list[str] | None = None,
        dry_run: bool = False,
        skip_analyst: bool = False,
        approve: bool = False,
    ):
        self.target = target.strip()
        self.llm = llm or LLMClient(LLMConfig())
        self.max_steps = max_steps
        self.modules_allowlist = modules_allowlist
        self.dry_run = dry_run
        self.skip_analyst = skip_analyst
        # Human-in-the-loop: ask before each specialist tool run
        self.approve = approve or (
            str(__import__("os").environ.get("RECON_AGENT_APPROVE", "")).lower()
            in ("1", "true", "yes", "on")
        )

        self.planner = PlannerAgent(self.llm)
        self.analyst = AnalystAgent(self.llm)
        self._agents: dict[str, SpecialistAgent] = {
            name: SpecialistAgent(name, self.llm) for name in AGENT_MODULES
        }

    def run(self) -> ReconState:
        require_scope(self.target)
        outdir = prepare_outdir(self.target)
        state = ReconState.load_or_create(self.target, outdir)
        state.status = "running"
        state.save()

        all_modules = list_modules()
        if self.modules_allowlist:
            allow = set(self.modules_allowlist)
            all_modules = [m for m in all_modules if m in allow]

        # Full mission tile list for the dashboard (all phases this agent run may hit)
        try:
            from live_mission import start_run, finish_run, mark_stopped
            pending = [m for m in all_modules if m not in state.completed_modules]
            start_run(
                target=self.target,
                modules=pending or list(all_modules),
                outdir=outdir,
                source="agent",
            )
        except Exception:
            pass

        self._print_header(state)

        for step_i in range(1, self.max_steps + 1):
            plan = self.planner.plan(state, all_modules)
            self._print_plan(step_i, plan)

            if plan.get("done"):
                state.status = "completed"
                state.save()
                break

            agent_name = plan.get("next_agent") or "subdomain"
            modules = plan.get("modules") or []

            if self.dry_run:
                state.add_step(AgentStep(
                    agent=agent_name,
                    modules=modules,
                    reasoning=plan.get("reasoning", ""),
                    summary="[dry-run] modules not executed",
                    timestamp=_now(),
                    success=True,
                    details={"dry_run": True, "plan": plan},
                ))
                # Simulate completion so planner can advance in dry-run demos
                for m in modules:
                    state.mark(m)
                state.save()
                continue

            if self.approve and modules:
                print(
                    f"\n[approve] Agent '{agent_name}' wants modules: "
                    f"{', '.join(modules)}"
                )
                print(f"[approve] Reasoning: {plan.get('reasoning', '')[:300]}")
                try:
                    ans = input("[approve] run these tools? [y/N/skip/quit]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    ans = "quit"
                if ans in ("q", "quit"):
                    state.status = "stopped"
                    state.save()
                    print("Stopped by operator.")
                    break
                if ans in ("s", "skip", "n", "no", ""):
                    print("[approve] skipped this step.")
                    state.add_step(AgentStep(
                        agent=agent_name,
                        modules=modules,
                        reasoning=plan.get("reasoning", ""),
                        summary="[approve] operator skipped",
                        timestamp=_now(),
                        success=True,
                        details={"skipped": True},
                    ))
                    # Do not mark modules complete so planner can re-propose
                    state.save()
                    continue
                if ans not in ("y", "yes"):
                    print("[approve] unrecognized answer — skipping.")
                    continue

            agent = self._agents.get(agent_name)
            if agent is None:
                # Fall back: pick agent that owns first module
                agent = self._pick_agent_for(modules)
            if agent is None:
                state.status = "failed"
                state.add_step(AgentStep(
                    agent=str(agent_name),
                    modules=modules,
                    reasoning=plan.get("reasoning", ""),
                    summary=f"No specialist agent for '{agent_name}'",
                    timestamp=_now(),
                    success=False,
                ))
                state.save()
                break

            print(f"\n>>> Running agent '{agent.name}' modules={modules}")
            result = agent.run(state, modules=modules)
            state.add_step(AgentStep(
                agent=result.agent,
                modules=result.modules_run or modules,
                reasoning=plan.get("reasoning", "") or result.reasoning,
                summary=result.summary,
                timestamp=_now(),
                success=result.success,
                details={"tool_results": result.details.get("tool_results", [])},
            ))
            state.save()
            self._print_agent_result(result)

            if not result.success and not result.modules_run:
                # Avoid infinite loop if an agent keeps failing with no progress
                print("! Agent made no progress; stopping to avoid a retry loop.")
                state.status = "failed"
                state.save()
                break
        else:
            state.status = "stopped"
            state.save()
            print(f"\nReached max_steps={self.max_steps}; stopping.")

        report_path = Path(state.outdir) / "agent_report.md"
        if not self.skip_analyst and not self.dry_run:
            print("\n>>> Analyst agent writing final report…")
            report = self.analyst.report(state)
            report_path.write_text(report, encoding="utf-8")
            print(f"Report saved: {report_path}")
        elif self.dry_run:
            report_path.write_text(
                f"# Dry-run plan for {state.target}\n\n"
                + "\n".join(
                    f"- step: {h.get('agent')} → {h.get('modules')} — {h.get('reasoning')}"
                    for h in state.history
                ),
                encoding="utf-8",
            )

        print(f"\nStatus: {state.status}")
        print(f"Completed modules: {', '.join(state.completed_modules) or '(none)'}")
        print(f"State: {Path(state.outdir) / 'agent_state.json'}")
        print(f"Outputs: {state.outdir}")
        try:
            from live_mission import finish_run, mark_stopped
            from run_control import CONTROL
            if CONTROL.is_stopped() or state.status in ("failed", "stopped"):
                mark_stopped(f"agent {state.status}")
            else:
                finish_run(ok=state.status == "completed", outdir=str(state.outdir))
        except Exception:
            pass
        return state

    def _pick_agent_for(self, modules: list[str]) -> SpecialistAgent | None:
        for name, owned in AGENT_MODULES.items():
            if any(m in owned for m in modules):
                return self._agents[name]
        return None

    def _print_header(self, state: ReconState) -> None:
        cfg = self.llm.config
        print("=" * 64)
        print(f"  Recon Agents  |  target={state.target}")
        print(f"  LLM: provider={cfg.provider}  model={cfg.model}")
        print(f"  outdir={state.outdir}")
        print(f"  already completed: {state.completed_modules or '(none)'}")
        print(f"  max_steps={self.max_steps}  dry_run={self.dry_run}")
        print("=" * 64)

    @staticmethod
    def _print_plan(step_i: int, plan: dict[str, Any]) -> None:
        print(f"\n--- Step {step_i}: PLANNER ---")
        print(f"  done={plan.get('done')}  priority={plan.get('priority')}")
        print(f"  next_agent={plan.get('next_agent')}  modules={plan.get('modules')}")
        reasoning = (plan.get("reasoning") or "").strip()
        if reasoning:
            # keep console readable
            short = reasoning if len(reasoning) < 400 else reasoning[:400] + "…"
            print(f"  reasoning: {short}")

    @staticmethod
    def _print_agent_result(result) -> None:
        print(f"\n--- Agent '{result.agent}' result (success={result.success}) ---")
        print(f"  modules_run: {result.modules_run}")
        summary = (result.summary or "").strip()
        if summary:
            short = summary if len(summary) < 800 else summary[:800] + "…"
            print(short)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
