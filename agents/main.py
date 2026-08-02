#!/usr/bin/env python3
"""
CLI for multi-agent recon orchestration.

Global LLM settings live in config/agent_config.json (see `config` subcommand).
Typical layout: recon agents inside a VM, Ollama + qwen3:8b on the Windows host.

Examples:
  # Local Ollama
  python recon_agents.py config set --provider ollama --base-url http://127.0.0.1:11434 --model qwen3:8b

  # Cloud (Grok / Claude / OpenAI / Gemini / …)
  python recon_agents.py providers
  python recon_agents.py config set --provider xai --model grok-2-latest
  # export XAI_API_KEY=...
  python recon_agents.py config set --provider anthropic --model claude-sonnet-4-20250514
  # export ANTHROPIC_API_KEY=...
  python recon_agents.py check-llm
  python recon_agents.py run --target example.com
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from agents.config import (  # noqa: E402
    GLOBAL_CONFIG_PATH,
    REPO_CONFIG_PATH,
    apply_cli_overrides,
    config_summary,
    init_config,
    load_config,
    save_config,
)
from agents.llm import LLMClient  # noqa: E402
from agents.orchestrator import ReconOrchestrator  # noqa: E402
from agents.specialists import AGENT_MODULES  # noqa: E402
from agents.tools import list_modules, module_descriptions  # noqa: E402


def _add_llm_flags(p: argparse.ArgumentParser, *, require_defaults: bool = False) -> None:
    """
    LLM flags override agent_config.json when set.
    Defaults are None/empty so we don't clobber the file with argparse defaults.
    """
    p.add_argument(
        "--config",
        default="",
        help="Path to agent_config.json (default: auto-discover under config/)",
    )
    p.add_argument(
        "--provider",
        default=None,
        help=(
            "LLM provider: ollama | openai | xai|grok | anthropic|claude | "
            "google|gemini|gemma | openrouter | groq | deepseek | together | "
            "mistral | fireworks | custom  (see: recon_agents.py providers)"
        ),
    )
    p.add_argument(
        "--model",
        default=None,
        help="Model id (e.g. qwen3:8b, grok-2-latest, claude-sonnet-4-20250514, gemini-2.0-flash)",
    )
    p.add_argument(
        "--base-url",
        default=None,
        help="API base URL (Ollama host IP, or cloud OpenAI-compat base; cloud has defaults)",
    )
    p.add_argument("--api-key", default=None, help="API key (or use provider env var)")
    p.add_argument("--temperature", type=float, default=None)
    p.add_argument("--timeout", type=int, default=None, help="LLM HTTP timeout seconds")
    p.add_argument(
        "--openai-compat",
        action="store_true",
        default=None,
        help="Force OpenAI-compatible /v1 API (mainly for Ollama)",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon-agents",
        description=(
            "Multi-agent bug-bounty recon orchestrator. "
            "LLM: local Ollama or cloud (xAI/Grok, Anthropic/Claude, OpenAI, "
            "Google Gemini/Gemma, OpenRouter, Groq, …). "
            "Config file → env → CLI. See: providers, check-llm, config set."
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    prov_p = sub.add_parser(
        "providers",
        help="List supported LLM providers (local + cloud) and default models/keys",
    )
    prov_p.set_defaults(func_name="providers")

    # --- run ---
    run_p = sub.add_parser("run", help="Run the multi-agent recon loop on an in-scope target")
    run_p.add_argument("--target", required=True, help="Target domain (must be in ~/.reconkit/scope.txt)")
    _add_llm_flags(run_p)
    run_p.add_argument("--max-steps", type=int, default=None, help="Override orchestrator.max_steps")
    run_p.add_argument(
        "--modules",
        default="",
        help="Optional comma-separated allowlist of reconkit modules (default: config or all)",
    )
    run_p.add_argument("--dry-run", action="store_true", help="Plan only; do not execute recon tools")
    run_p.add_argument("--skip-analyst", action="store_true", help="Skip final analyst report")
    run_p.add_argument(
        "--debug", action="store_true",
        help="Shortcut for --verbose 2 (reconkit debug diagnostics)",
    )
    run_p.add_argument(
        "-v", "--verbose", type=int, default=None, metavar="LEVEL", choices=[0, 1, 2, 3],
        help="reconkit verbosity: 0=quiet 1=normal 2=debug 3=live tool streams",
    )
    run_p.add_argument(
        "--approve",
        action="store_true",
        help="Human-in-the-loop: confirm each agent tool step before running",
    )

    # --- agents / modules ---
    sub.add_parser("agents", help="List specialist agents and their modules")
    sub.add_parser("modules", help="List reconkit modules available to agents")

    # --- check-llm ---
    check_p = sub.add_parser(
        "check-llm",
        help="Ping configured LLM and (for Ollama) list models on that host",
    )
    _add_llm_flags(check_p)

    # --- config ---
    cfg_p = sub.add_parser("config", help="Show / init / set global agent LLM config")
    cfg_sub = cfg_p.add_subparsers(dest="config_action", required=True)

    show_p = cfg_sub.add_parser("show", help="Print effective config (file + env)")
    show_p.add_argument("--config", default="", help="Config file path")
    show_p.add_argument("--json", action="store_true", help="Print raw JSON")

    init_p = cfg_sub.add_parser(
        "init",
        help="Write a starter agent_config.json for VM → Windows Ollama",
    )
    init_p.add_argument(
        "--path",
        default="",
        help=f"Where to write (default: {GLOBAL_CONFIG_PATH})",
    )
    init_p.add_argument(
        "--repo",
        action="store_true",
        help=f"Write to repo file instead ({REPO_CONFIG_PATH})",
    )
    init_p.add_argument(
        "--base-url",
        default="http://127.0.0.1:11434",
        help="Ollama URL. For a VM use the Windows host IP, e.g. http://192.168.1.50:11434",
    )
    init_p.add_argument("--model", default="qwen3:8b", help="Default model tag")
    init_p.add_argument("--provider", default="ollama")
    init_p.add_argument("--force", action="store_true", help="Overwrite existing file")

    set_p = cfg_sub.add_parser("set", help="Update keys in the config file")
    set_p.add_argument("--config", default="", help="Config file to edit (default: discovered or global)")
    set_p.add_argument("--provider", default=None)
    set_p.add_argument("--model", default=None)
    set_p.add_argument("--base-url", default=None)
    set_p.add_argument("--api-key", default=None)
    set_p.add_argument("--temperature", type=float, default=None)
    set_p.add_argument("--timeout", type=int, default=None)
    set_p.add_argument("--max-steps", type=int, default=None)
    set_p.add_argument(
        "--openai-compat",
        choices=["true", "false"],
        default=None,
        help="Set llm.use_openai_compat",
    )

    path_p = cfg_sub.add_parser("path", help="Print which config file would be loaded")
    path_p.add_argument("--config", default="")

    return p


def _build_agent_config(args) -> object:
    path = getattr(args, "config", None) or None
    path = path if path else None
    cfg = load_config(path)
    use_compat = None
    if getattr(args, "openai_compat", None) is True:
        use_compat = True
    cfg = apply_cli_overrides(
        cfg,
        provider=getattr(args, "provider", None),
        model=getattr(args, "model", None),
        base_url=getattr(args, "base_url", None),
        api_key=getattr(args, "api_key", None),
        temperature=getattr(args, "temperature", None),
        timeout=getattr(args, "timeout", None),
        max_steps=getattr(args, "max_steps", None),
        use_openai_compat=use_compat,
    )
    return cfg


def cmd_agents(_args) -> None:
    print("Specialist agents\n" + "-" * 40)
    for name, mods in AGENT_MODULES.items():
        print(f"  {name:12}  modules: {', '.join(mods)}")
    print("\nAlso: planner (decides next step), analyst (final report)")
    try:
        from agents.skills import skill_status

        st = skill_status()
        print("\nAgent skill\n" + "-" * 40)
        if st.get("enabled"):
            print(f"  primary: {st.get('name')}")
            print(f"  path:    {st.get('path')}")
            suite = st.get("suite") or {}
            if suite:
                print("  suite by role:")
                for role, names in suite.items():
                    print(f"    {role:12} {', '.join(names)}")
        else:
            print("  primary: (disabled — RECON_AGENT_SKILL=off)")
        for s in st.get("available") or []:
            print(f"  avail:   {s.get('name')} — {(s.get('description') or '')[:70]}")
        print("  env:     RECON_AGENT_SKILL=reconkit-bug-bounty | off")
        print("           RECON_AGENT_SKILL_EXTRA=skill1,skill2")
        print("           RECON_AGENT_SKILL_MAX=14000")
        surf = st.get("surface_skills") or []
        if surf:
            print("  surface: (on-demand) " + ", ".join(surf))
        print("  index:   skills/SKILLS_INDEX.md")
    except Exception as e:
        print(f"\n  (skill status unavailable: {e})")


def cmd_modules(_args) -> None:
    descs = module_descriptions()
    print("reconkit modules available to agents\n" + "-" * 40)
    for m in list_modules():
        print(f"  {m:12}  {descs.get(m, '')}")


def cmd_providers(_args) -> None:
    from agents.llm import list_providers

    print("Supported LLM providers (local + cloud)\n" + "-" * 60)
    print(f"  {'provider':12} {'api':10} {'default_model':36} key_env")
    print(f"  {'--------':12} {'---':10} {'-------------':36} -------")
    for p in list_providers():
        print(
            f"  {p['provider']:12} {p['api']:10} {(p['default_model'] or '-'):36} "
            f"{p.get('key_env') or '-'}"
        )
    print(
        "\nExamples:\n"
        "  # Local Ollama\n"
        "  python recon_agents.py config set --provider ollama "
        "--base-url http://127.0.0.1:11434 --model qwen3:8b\n"
        "\n"
        "  # xAI Grok\n"
        "  setx XAI_API_KEY \"xai-...\"   # or export XAI_API_KEY=...\n"
        "  python recon_agents.py config set --provider xai --model grok-2-latest\n"
        "\n"
        "  # Anthropic Claude\n"
        "  export ANTHROPIC_API_KEY=sk-ant-...\n"
        "  python recon_agents.py config set --provider anthropic "
        "--model claude-sonnet-4-20250514\n"
        "\n"
        "  # OpenAI\n"
        "  export OPENAI_API_KEY=sk-...\n"
        "  python recon_agents.py config set --provider openai --model gpt-4o-mini\n"
        "\n"
        "  # Google Gemini / Gemma\n"
        "  export GOOGLE_API_KEY=...\n"
        "  python recon_agents.py config set --provider google --model gemini-2.0-flash\n"
        "  python recon_agents.py config set --provider gemma --model gemma-3-27b-it\n"
        "\n"
        "  # OpenRouter (many models)\n"
        "  export OPENROUTER_API_KEY=...\n"
        "  python recon_agents.py config set --provider openrouter "
        "--model anthropic/claude-3.5-sonnet\n"
        "\n"
        "  python recon_agents.py check-llm\n"
        "  python recon_agents.py run --target example.com --provider xai --model grok-2-latest\n"
    )


def cmd_check_llm(args) -> None:
    cfg = _build_agent_config(args)
    print("Effective LLM config:")
    print(config_summary(cfg))
    print()
    client = LLMClient(cfg)
    c = client.config
    print(
        f"Pinging provider={c.provider} model={c.model} base_url={c.base_url} "
        f"api_key={'set' if c.api_key else 'empty'} …"
    )

    if c.provider != "ollama" and not c.api_key:
        print(
            "WARNING: no API key set for cloud provider. "
            "Set RECON_LLM_API_KEY or the provider-specific env (see providers).",
            file=sys.stderr,
        )

    if c.provider == "ollama":
        try:
            models = client.list_ollama_models()
            print(f"Ollama reachable — models on host: {', '.join(models) or '(none)'}")
            if c.model and c.model not in models:
                if not any(
                    m == c.model or m.startswith(c.model + ":") or c.model in m
                    for m in models
                ):
                    print(
                        f"WARNING: model '{c.model}' not found in ollama list. "
                        f"On the host run: ollama pull {c.model}"
                    )
        except Exception as e:
            print(f"FAILED (tags): {e}", file=sys.stderr)
            _print_llm_connect_help(c.provider, c.base_url, e)
            sys.exit(1)

    try:
        reply = client.ping()
        print(f"OK — model replied: {reply.strip()[:200]}")
    except Exception as e:
        print(f"FAILED (chat): {e}", file=sys.stderr)
        _print_llm_connect_help(c.provider, c.base_url, e)
        sys.exit(1)


def _print_llm_connect_help(provider: str, base_url: str, err: BaseException) -> None:
    """Hints for Ollama reachability or missing cloud credentials."""
    msg = str(err).lower()
    if provider != "ollama":
        if "api key" in msg or "401" in msg or "auth" in msg or "permission" in msg:
            print(
                "\nCloud auth failed. Set the provider API key, e.g.:\n"
                "  export RECON_LLM_API_KEY=...\n"
                "  # or: XAI_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY / "
                "GOOGLE_API_KEY / OPENROUTER_API_KEY / GROQ_API_KEY\n"
                "  python recon_agents.py providers\n"
                "  python recon_agents.py check-llm\n",
                file=sys.stderr,
            )
        return

    refused = "111" in msg or "connection refused" in msg or "actively refused" in msg
    timeout = "timed out" in msg or "timeout" in msg
    if not (refused or timeout):
        return
    print(
        "\n"
        "Ollama is not reachable at the configured base_url.\n"
        "\n"
        "Common VM → Windows-host mistake:\n"
        "  base_url must be the WINDOWS host IP (where Ollama runs),\n"
        "  NOT the Kali/VM IP and NOT 127.0.0.1 inside the VM.\n"
        "\n"
        f"  current base_url: {base_url}\n"
        "\n"
        "From this machine, find a working host:\n"
        "  curl -s http://<WINDOWS_HOST_IP>:11434/api/tags\n"
        "  # success looks like JSON with a \"models\" list\n"
        "\n"
        "Then point the agents at it:\n"
        "  python recon_agents.py config set --base-url http://<WINDOWS_HOST_IP>:11434\n"
        "  python recon_agents.py check-llm\n"
        "\n"
        "Or switch to cloud LLM:\n"
        "  python recon_agents.py config set --provider xai --model grok-2-latest\n"
        "  export XAI_API_KEY=...\n"
        "\n"
        "On Windows (once):\n"
        "  setx OLLAMA_HOST 0.0.0.0\n"
        "  # restart Ollama app/service, allow TCP 11434 in firewall\n"
        "  ollama pull qwen3:8b\n",
        file=sys.stderr,
    )


def cmd_run(args) -> None:
    from agents.tools import get_reconkit
    rk = get_reconkit()
    # Prefer explicit --verbose; --debug maps to level 2
    if getattr(args, "verbose", None) is not None:
        rk.set_verbose(args.verbose)
    elif args.debug:
        rk.set_verbose(2)

    cfg = _build_agent_config(args)

    allow = None
    if args.modules.strip():
        allow = [m.strip() for m in args.modules.split(",") if m.strip()]
    elif cfg.orchestrator.modules:
        allow = list(cfg.orchestrator.modules)

    skip_analyst = args.skip_analyst or cfg.orchestrator.skip_analyst

    print("Using LLM config:")
    print(config_summary(cfg))
    print()

    client = LLMClient(cfg)
    orch = ReconOrchestrator(
        target=args.target,
        llm=client,
        max_steps=cfg.orchestrator.max_steps,
        modules_allowlist=allow,
        dry_run=args.dry_run,
        skip_analyst=skip_analyst,
        approve=bool(getattr(args, "approve", False)),
    )
    state = orch.run()
    if state.status == "failed":
        sys.exit(2)


def cmd_config(args) -> None:
    action = args.config_action
    if action == "show":
        cfg = load_config(args.config or None)
        if args.json:
            print(json.dumps(cfg.to_dict(), indent=2))
        else:
            print(config_summary(cfg))
        return

    if action == "path":
        from agents.config import discover_config_path
        p = discover_config_path(args.config or None)
        if p and p.exists():
            print(p)
        elif args.config:
            print(f"(not found) {Path(args.config).expanduser().resolve()}")
            sys.exit(1)
        else:
            print(f"(no file yet — would create) {GLOBAL_CONFIG_PATH}")
        return

    if action == "init":
        if args.repo:
            path = REPO_CONFIG_PATH
        elif args.path:
            path = Path(args.path)
        else:
            path = GLOBAL_CONFIG_PATH
        try:
            written = init_config(
                path,
                base_url=args.base_url,
                model=args.model,
                provider=args.provider,
                force=args.force,
            )
        except FileExistsError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        print(f"Wrote {written}")
        print(config_summary(load_config(written)))
        print(
            "\nIf agents run in a VM: set base_url to the Windows host IP, not 127.0.0.1.\n"
            "On Windows host:\n"
            "  setx OLLAMA_HOST 0.0.0.0\n"
            "  (restart Ollama)  ollama pull qwen3:8b\n"
            "  Allow firewall TCP 11434\n"
        )
        return

    if action == "set":
        from agents.config import discover_config_path
        path_str = args.config or None
        existing = discover_config_path(path_str)
        if path_str and not Path(path_str).expanduser().exists():
            # create new at that path from defaults + set values
            path = Path(path_str).expanduser().resolve()
            cfg = load_config(None)
            cfg.source_path = ""
        elif existing and existing.exists():
            path = existing
            cfg = load_config(path)
        else:
            path = GLOBAL_CONFIG_PATH
            cfg = load_config(None)

        use_compat = None
        if args.openai_compat == "true":
            use_compat = True
        elif args.openai_compat == "false":
            use_compat = False

        cfg = apply_cli_overrides(
            cfg,
            provider=args.provider,
            model=args.model,
            base_url=args.base_url,
            api_key=args.api_key,
            temperature=args.temperature,
            timeout=args.timeout,
            max_steps=args.max_steps,
            use_openai_compat=use_compat,
        )
        # apply_cli_overrides only sets use_openai_compat when not None;
        # for false we need explicit assignment:
        if args.openai_compat == "false":
            cfg.llm.use_openai_compat = False

        saved = save_config(cfg, path)
        print(f"Updated {saved}")
        print(config_summary(load_config(saved)))
        return

    print(f"Unknown config action: {action}", file=sys.stderr)
    sys.exit(1)


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run":
        cmd_run(args)
    elif args.command == "agents":
        cmd_agents(args)
    elif args.command == "modules":
        cmd_modules(args)
    elif args.command == "providers":
        cmd_providers(args)
    elif args.command == "check-llm":
        cmd_check_llm(args)
    elif args.command == "config":
        cmd_config(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
