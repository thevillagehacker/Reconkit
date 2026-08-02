"""
Command registry for the interactive cyber shell.

Slash commands (preferred):  /help  /run  /scan  …
Bare commands also accepted:  help   run   scan  …
Typing just `/` lists every available command.

INLINE HELP (every command)
---------------------------
  /<command> -h
  /<command> --help
  /<command> -?
  /<command> /?
  /<command> help

This is resolved in the shell dispatcher for ALL registered commands
(not only /agents). You do not need external scripts to learn usage.
"""

from __future__ import annotations

from dataclasses import dataclass


# Recognized on EVERY slash command via ReconShell._dispatch
HELP_FLAGS = frozenset({
    "-h",
    "--help",
    "-?",
    "/?",
    "help",
})


@dataclass
class Command:
    name: str
    aliases: list[str]
    usage: str
    summary: str
    help_text: str
    category: str
    handler: str  # method name on ReconShell
    min_args: int = 0
    max_args: int | None = None
    # Shown in the `/` slash menu and used for tab completion
    subcommands: list[str] | None = None
    # Optional common flags shown under the command in the slash menu
    flags: list[str] | None = None


def _ht(*lines: str) -> str:
    return "\n".join(lines)


# Subcommands only (not flags / values). Flag values live in shell/suggestions.py
_SUBCOMMAND_MAP: dict[str, list[str]] = {
    "scope": ["add", "list", "check"],
    "keys": ["set", "list", "remove"],
    "config": ["show", "path", "init", "set"],
    "findings": ["reindex", "summary"],
    "playbook": ["list", "run"],
    "jobs": ["list", "status"],
    "verbose": ["0", "1", "2", "3", "quiet", "normal", "debug", "live"],
    "rate": ["show", "stealth", "normal", "aggressive"],
    "prove": ["policy", "techniques", "queue", "run", "list", "show"],
    "program": ["list", "show", "set"],
    "graph": ["show", "summary"],
    "help": [],  # dynamic: command names via suggestions
}

# Flags (first token). Value catalogs: shell/suggestions.py
_FLAG_MAP: dict[str, list[str]] = {
    "run": ["--modules a,b,c|all", "--bg", "--fg"],
    "agent": ["--dry-run", "--approve", "--modules a,b", "--max-steps N", "--skip-analyst"],
    "config": [
        "--provider", "--model", "--base-url", "--api-key",
        "--temperature", "--timeout", "--max-steps",
        "--openai-compat", "--repo", "--force", "--json",
    ],
    "dashboard": ["--host 0.0.0.0|127.0.0.1", "--port N", "--no-browser"],
    "report": ["--all"],
    "notable": ["--limit N"],
    "prove": ["--technique name", "--limit N", "--all", "--dry-run"],
    "graph": ["--min-score N"],
}


# Canonical command table — single source of truth for /help and /cmd -h
COMMANDS: list[Command] = [
    # --- shell / meta ---
    Command(
        "help", ["?", "h", "usage"],
        "/help [cmd]",
        "Show all commands, or detailed help for one",
        _ht(
            "Inline help works on EVERY command (not just /agents):",
            "  /run -h          /scan --help       /scope -?",
            "  /keys help       /agent -h          /dashboard --help",
            "  /verbose -h      /findings -h       /config --help",
            "",
            "Catalog forms:",
            "  /help            full catalog of every command",
            "  /help run        same details as /run -h",
            "  /                list all slash names",
            "  /commands        same as /",
            "",
            "You should not need external docs for day-to-day usage —",
            "append -h or --help to any command you are unsure about.",
        ),
        "shell", "cmd_help",
    ),
    Command(
        "commands", ["cmds", "ls"],
        "/commands",
        "List every slash command (same as typing /)",
        _ht(
            "Prints the full slash-command index in columns.",
            "",
            "Examples:",
            "  /commands",
            "  /cmds",
            "  /",
            "",
            "Then drill into any name:",
            "  /modules -h",
            "  /agent --help",
        ),
        "shell", "cmd_list_commands",
    ),
    Command(
        "banner", [],
        "/banner",
        "Re-draw the cyber banner",
        _ht(
            "Reprints the reconkit ASCII banner and quick tips.",
            "Useful after /clear or a long scroll of scan output.",
            "",
            "Examples:",
            "  /banner",
        ),
        "shell", "cmd_banner",
    ),
    Command(
        "clear", ["cls"],
        "/clear",
        "Clear the terminal",
        _ht(
            "Clears the screen (cls on Windows, clear on Unix).",
            "",
            "Examples:",
            "  /clear",
            "  /cls",
        ),
        "shell", "cmd_clear",
    ),
    Command(
        "status", ["info", "whoami"],
        "/status",
        "Show target, verbose level, paths, LLM config",
        _ht(
            "Session snapshot:",
            "  • active /target",
            "  • verbose level (0–3)",
            "  • ~/.reconkit paths (output, scope)",
            "  • in-scope domains",
            "  • effective agent LLM config (if loadable)",
            "",
            "Examples:",
            "  /status",
            "  /info",
        ),
        "shell", "cmd_status",
    ),
    Command(
        "verbose", ["v", "debug"],
        "/verbose <0-3|quiet|normal|debug|live>",
        "Set verbosity / debug level",
        _ht(
            "Controls how much reconkit prints while tools run.",
            "",
            "Levels:",
            "  0  quiet   — banners + OK/WARN/FAIL mainly",
            "  1  normal  — $ command lines + stage progress (default)",
            "  2  debug   — + timing, exit codes, stderr snippets, file diffs",
            "  3  live    — + full live stdout/stderr of every tool",
            "",
            "Examples:",
            "  /verbose              show current level",
            "  /verbose 2",
            "  /verbose live",
            "  /verbose debug",
            "  /debug 3              alias of /verbose",
            "",
            "Note: --debug on reconkit.py CLI is the same as level 2.",
        ),
        "shell", "cmd_verbose", max_args=1,
    ),
    Command(
        "target", ["t", "set-target"],
        "/target [domain]",
        "Set or show the active scan target",
        _ht(
            "Session default for /run /scan /quick /full /agent /outdir when",
            "you omit the domain argument.",
            "",
            "Does NOT add scope — use /scope add for authorization.",
            "",
            "Examples:",
            "  /target",
            "  /target example.com",
            "  /t example.com",
        ),
        "shell", "cmd_target", max_args=1,
    ),
    Command(
        "exit", ["quit", "q"],
        "/exit",
        "Leave the shell",
        _ht(
            "Exits the interactive prompt cleanly.",
            "",
            "Examples:",
            "  /exit",
            "  /quit",
            "  /q",
            "",
            "Ctrl+C asks for confirm; /exit is immediate.",
        ),
        "shell", "cmd_exit",
    ),
    # --- setup / env ---
    Command(
        "checkenv", ["env"],
        "/checkenv",
        "Check OS, tools prerequisites, API key visibility",
        _ht(
            "Reports OS, admin-ish privileges, git/go/python/cargo, and which",
            "optional API keys are visible (not their values).",
            "",
            "Examples:",
            "  /checkenv",
            "  /env",
            "",
            "CLI equivalent:  python reconkit.py checkenv",
        ),
        "setup", "cmd_checkenv",
    ),
    Command(
        "setup", ["install"],
        "/setup",
        "Install Go/Rust/Python tools, gf, nuclei templates",
        _ht(
            "Idempotent install of the recon toolkit:",
            "  Go tools, Cargo tools, pip --user tools, gf patterns,",
            "  nuclei templates, colorama, config under ~/.reconkit.",
            "",
            "Safe to re-run; skips what already exists.",
            "After setup, apply PATH lines it prints, then /verify.",
            "",
            "Examples:",
            "  /setup",
            "  /install",
            "",
            "CLI equivalent:  python reconkit.py setup",
        ),
        "setup", "cmd_setup",
    ),
    Command(
        "verify", [],
        "/verify",
        "Verify installed tools resolve on PATH",
        _ht(
            "Lists each expected binary and whether reconkit can find it.",
            "Run after /setup or on a new machine.",
            "",
            "Examples:",
            "  /verify",
            "",
            "CLI equivalent:  python reconkit.py verify",
        ),
        "setup", "cmd_verify",
    ),
    Command(
        "wordlists", ["wl"],
        "/wordlists",
        "Download SecLists, OneListForAll, resolvers",
        _ht(
            "Clones/downloads wordlists into ~/.reconkit/wordlists/.",
            "Used by content discovery and related stages.",
            "",
            "Examples:",
            "  /wordlists",
            "  /wl",
            "",
            "CLI equivalent:  python reconkit.py wordlists",
        ),
        "setup", "cmd_wordlists",
    ),
    # --- scope / keys ---
    Command(
        "scope", [],
        "/scope <add|list|check> [domain]",
        "Manage authorized targets (hard safety gate)",
        _ht(
            "Nothing in /run /scan /quick /full /agent runs without scope.",
            "Adding a domain requires typing 'yes' to confirm authorization.",
            "",
            "Subcommands:",
            "  add <domain>     authorize (wildcards like *.example.com OK)",
            "  list             show ~/.reconkit/scope.txt entries",
            "  check <domain>   test membership",
            "",
            "Examples:",
            "  /scope add example.com",
            "  /scope add *.example.com",
            "  /scope list",
            "  /scope check example.com",
            "",
            "CLI equivalent:  python reconkit.py scope …",
        ),
        "auth", "cmd_scope", min_args=1,
    ),
    Command(
        "keys", ["key"],
        "/keys <set|list|remove> [name] [value]",
        "Manage optional API keys (~/.reconkit/secrets.env)",
        _ht(
            "Optional keys boost subdomain yield (chaos, GitHub, Shodan, …).",
            "Stored only in ~/.reconkit/secrets.env — never in the repo.",
            "",
            "Subcommands:",
            "  list",
            "  set <NAME> <value>",
            "  remove <NAME>",
            "",
            "Common names:",
            "  PDCP_API_KEY  GITHUB_TOKEN  SHODAN_API_KEY",
            "  CENSYS_API_ID  SECURITYTRAILS_API_KEY  VIRUSTOTAL_API_KEY",
            "",
            "Examples:",
            "  /keys list",
            "  /keys set PDCP_API_KEY abcd1234",
            "  /keys remove SHODAN_API_KEY",
            "",
            "Wrong (extra 'set' — now auto-skipped if you upgrade):",
            "  /keys set set PDCP_API_KEY …",
            "",
            "CLI equivalent:  python reconkit.py keys set PDCP_API_KEY <token>",
            "File: ~/.reconkit/secrets.env  (chmod 600)",
        ),
        "auth", "cmd_keys", min_args=1,
    ),
    # --- recon pipeline ---
    Command(
        "modules", ["mods", "module"],
        "/modules",
        "List recon modules and descriptions",
        _ht(
            "Lists every reconkit stage you can pass to /run --modules …",
            "",
            "Modules include:",
            "  subdomains dns httpprobe tls crawl js params content",
            "  xss sqli ssrf_ssti nuclei cloud screenshots",
            "",
            "Examples:",
            "  /modules",
            "  /mods",
            "",
            "Then:  /run example.com --modules subdomains,httpprobe",
            "CLI equivalent:  python reconkit.py modules",
        ),
        "recon", "cmd_modules",
    ),
    Command(
        "scan", ["pick", "menu"],
        "/scan [target]",
        "Interactive picker — choose which modules to run",
        _ht(
            "Menu of all modules. Toggle with numbers, then run.",
            "Target: argument or active /target. Must be in /scope.",
            "",
            "Picker keys:",
            "  1..N     toggle module",
            "  a / all  select all",
            "  n / none clear all",
            "  d        sensible defaults",
            "  Enter/r  run selected",
            "  q        cancel",
            "",
            "Examples:",
            "  /scan",
            "  /scan example.com",
            "  /pick",
        ),
        "recon", "cmd_scan", max_args=1,
    ),
    Command(
        "run", ["recon", "pipeline"],
        "/run [target] [--modules a,b,c|all] [--fg]",
        "Run recon pipeline (background by default — use /pause /stop)",
        _ht(
            "Direct reconkit pipeline (no LLM). Detection only.",
            "Target must already be in /scope.",
            "",
            "Runs in BACKGROUND by default so you can:",
            "  /pause   — freeze between stages/hosts",
            "  /resume  — continue",
            "  /stop    — abort at next checkpoint",
            "  /jobs    — list jobs",
            "  /outdir T — inspect files while scanning",
            "",
            "Flags:",
            "  --modules / -m   comma-separated list, or 'all' (default all)",
            "  --fg             block the shell (foreground; Ctrl+C only)",
            "",
            "Examples:",
            "  /run example.com",
            "  /run example.com --modules subdomains,dns,httpprobe",
            "  /run example.com --fg",
            "",
            "Related: /quick  /full  /scan  /pause  /stop  /verbose",
            "CLI: python reconkit.py run --target T [--modules …]",
        ),
        "recon", "cmd_run",
    ),
    Command(
        "quick", ["fast"],
        "/quick [target]",
        "Quick recon: subdomains + dns + httpprobe",
        _ht(
            "Short high-signal pass: subdomain enum → DNS → live HTTP.",
            "Uses /target if domain omitted. Scope required.",
            "",
            "Examples:",
            "  /quick example.com",
            "  /target example.com",
            "  /quick",
            "",
            "Same as: /run T --modules subdomains,dns,httpprobe",
        ),
        "recon", "cmd_quick", max_args=1,
    ),
    Command(
        "full", ["all"],
        "/full [target]",
        "Full recon: every module",
        _ht(
            "Runs ALL reconkit modules (longest, noisiest pass).",
            "Uses /target if domain omitted. Scope required.",
            "",
            "Examples:",
            "  /full example.com",
            "  /full",
            "",
            "Prefer /scan or /run --modules … for focused hunts.",
            "Same as: /run T --modules all",
        ),
        "recon", "cmd_full", max_args=1,
    ),
    Command(
        "outdir", ["output", "results"],
        "/outdir [target]",
        "Show output directory for a target",
        _ht(
            "Prints ~/.reconkit/output/<target> and lists result files.",
            "Uses /target if domain omitted.",
            "",
            "Examples:",
            "  /outdir",
            "  /outdir example.com",
            "  /results example.com",
        ),
        "recon", "cmd_outdir", max_args=1,
    ),
    Command(
        "findings", ["index", "reindex"],
        "/findings [reindex|summary] [target]",
        "Build or show the unified findings index",
        _ht(
            "Parses ~/.reconkit/output into a JSON index used by /dashboard.",
            "Not a live DB — reindex after new scans.",
            "",
            "Forms:",
            "  /findings                 overall summary",
            "  /findings reindex         rebuild from disk",
            "  /findings summary         same as bare /findings",
            "  /findings summary T       per-target counts + notables",
            "  /findings T               per-target (shorthand)",
            "",
            "Examples:",
            "  /findings reindex",
            "  /findings summary example.com",
            "  /reindex                  alias → findings command",
            "",
            "CLI: python reconkit.py findings [reindex|summary] [target]",
        ),
        "recon", "cmd_findings",
    ),
    Command(
        "dashboard", ["dash", "ui", "serve"],
        "/dashboard [--port N] [--no-browser]",
        "Launch cyber web UI for findings (local server)",
        _ht(
            "Local HTTP UI over recon results (filter by target/module/",
            "severity/type).",
            "",
            "Flags:",
            "  --port N        listen port (default 8787)",
            "  --host H        bind address (default 0.0.0.0 = all interfaces,",
            "                  reachable from Windows host when run in a VM;",
            "                  use 127.0.0.1 for localhost-only)",
            "  --no-browser    do not open a browser tab",
            "  N               bare number also sets port: /dashboard 9000",
            "",
            "Examples:",
            "  /dashboard",
            "  /dashboard --port 9000 --no-browser",
            "  /dashboard --host 127.0.0.1   # local only",
            "  /dash 8787",
            "",
            "From Windows host (dashboard in VM): http://<VM_LAN_IP>:8787/",
            "This blocks the shell until Ctrl+C — use a second terminal if",
            "you still need the prompt. Do not expose the port to the internet.",
            "",
            "CLI: python recon_dashboard.py [--port …]",
            "Related: /findings reindex first if the UI looks empty/stale.",
        ),
        "recon", "cmd_dashboard",
    ),
    # --- multi-agent ---
    Command(
        "agents", ["agent-list"],
        "/agents",
        "List specialist LLM agents and their modules",
        _ht(
            "Shows which multi-agent specialist owns which reconkit modules:",
            "  subdomain → subdomains",
            "  discovery → dns, httpprobe, tls",
            "  content   → crawl, js, params, content",
            "  vuln      → xss, sqli, ssrf_ssti, nuclei, cloud",
            "  visual    → screenshots",
            "Plus planner (decides next step) and analyst (final report).",
            "",
            "Examples:",
            "  /agents",
            "  /agent-list",
            "",
            "This does NOT start a scan. To run the LLM loop: /agent <target>",
            "CLI: python recon_agents.py agents",
        ),
        "agents", "cmd_agents",
    ),
    Command(
        "agent", ["agent-run", "orchestrate"],
        "/agent [target] [--modules a,b] [--dry-run] [--max-steps N] [--approve]",
        "Multi-agent recon loop (planner + specialists + analyst)",
        _ht(
            "THIS is what contacts the LLM. Plain /run does not.",
            "Planner chooses next specialist; specialists call reconkit;",
            "analyst writes agent_report.md. Target must be in /scope.",
            "",
            "Flags:",
            "  --dry-run         plan only, do not execute tools",
            "  --modules a,b     allowlist of reconkit modules",
            "  --max-steps N     planner loop limit",
            "  --skip-analyst    skip final report",
            "  --approve         human-in-the-loop: confirm each tool step",
            "",
            "Examples:",
            "  /agent example.com",
            "  /agent --dry-run",
            "  /agent example.com --approve",
            "  /agent example.com --modules subdomains,dns,httpprobe --max-steps 6",
            "",
            "Prereq: /check-llm   Config: /config show",
            "CLI: python recon_agents.py run --target T [--approve] …",
        ),
        "agents", "cmd_agent",
    ),
    Command(
        "check-llm", ["llm", "ping-llm"],
        "/check-llm",
        "Ping configured Ollama / online LLM",
        _ht(
            "Prints effective LLM config, lists Ollama models (if ollama),",
            "and sends a short ping chat. Use before /agent.",
            "",
            "Examples:",
            "  /check-llm",
            "  /llm",
            "",
            "CLI: python recon_agents.py check-llm",
            "If it fails: /config show and fix base_url / model / API key.",
        ),
        "agents", "cmd_check_llm",
    ),
    Command(
        "config", ["cfg"],
        "/config <show|path|init|set> [--flags…]",
        "Show / init / update agent LLM config",
        _ht(
            "Manages agent_config.json (Ollama / OpenAI-compatible providers).",
            "Always use --flag form (same as recon_agents.py). Bare keys are rejected.",
            "",
            "Subcommands:",
            "  show [--json]     effective config",
            "  path              which file would load",
            "  init [--repo] [--base-url U] [--model M] [--provider P] [--force]",
            "  set  --base-url U [--model M] [--provider P] [--api-key K]",
            "       [--temperature T] [--timeout N] [--max-steps N]",
            "       [--openai-compat true|false]",
            "",
            "Examples:",
            "  /config show",
            "  /config path",
            "  /config init --repo --base-url http://127.0.0.1:11434 --model qwen3:8b",
            "  /config set --base-url http://192.168.1.4:11434",
            "  /config set --model qwen3:8b --timeout 300",
            "",
            "Cloud providers (also: python recon_agents.py providers):",
            "  /config set --provider xai --model grok-2-latest",
            "  /config set --provider anthropic --model claude-sonnet-4-20250514",
            "  /config set --provider openai --model gpt-4o-mini",
            "  /config set --provider google --model gemini-2.0-flash",
            "  /config set --provider gemma --model gemma-3-27b-it",
            "  /config set --provider openrouter --model google/gemma-2-27b-it",
            "  /config set --provider groq --model llama-3.3-70b-versatile",
            "",
            "Keys via env: XAI_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY,",
            "  GOOGLE_API_KEY, OPENROUTER_API_KEY, GROQ_API_KEY, RECON_LLM_API_KEY",
            "",
            "Wrong:  /config set base_url http://…",
            "Right:  /config set --base-url http://…",
            "",
            "After set: /config show  then  /check-llm",
            "CLI: python recon_agents.py config set --provider xai --model grok-2-latest",
        ),
        "agents", "cmd_config", min_args=1,
    ),
    # --- Tier A+ analyst / jobs / playbooks ---
    Command(
        "notable", ["top"],
        "/notable [target] [--limit N]",
        "Show highest-scored recon records (notable only)",
        _ht(
            "Uses findings index scores (secrets, takeovers, high/critical, …).",
            "Run /findings reindex first if empty.",
            "",
            "Examples:",
            "  /notable",
            "  /notable example.com",
            "  /notable example.com --limit 30",
        ),
        "recon", "cmd_notable",
    ),
    Command(
        "diff", ["delta"],
        "/diff [target]",
        "What changed since last reindex (per-target history)",
        _ht(
            "Compares the last two findings snapshots for a target.",
            "Snapshots are written automatically on each /findings reindex.",
            "",
            "Examples:",
            "  /diff",
            "  /diff example.com",
        ),
        "recon", "cmd_diff", max_args=1,
    ),
    Command(
        "report", ["draft"],
        "/report [target] [--all]",
        "Write markdown report draft from index (notable by default)",
        _ht(
            "Writes report_draft.md under ~/.reconkit/output/<target>/.",
            "",
            "Examples:",
            "  /report",
            "  /report example.com",
            "  /report example.com --all   # include non-notable rows",
        ),
        "recon", "cmd_report",
    ),
    Command(
        "playbook", ["pb", "recipe"],
        "/playbook <list|run> [name] [target]",
        "Named module recipes (quick, js-deep, vuln-pass, …)",
        _ht(
            "Subcommands:",
            "  list              show playbooks",
            "  run <name> [t]    run modules for playbook",
            "",
            "Examples:",
            "  /playbook list",
            "  /playbook run quick example.com",
            "  /playbook run js-deep",
            "  /pb run vuln-pass example.com",
        ),
        "recon", "cmd_playbook", min_args=1,
    ),
    Command(
        "pause", [],
        "/pause",
        "Pause the active background scan",
        _ht(
            "Pauses at the next stage/host checkpoint.",
            "  /pause",
            "  /resume",
            "  /stop",
            "  /outdir <target>",
        ),
        "recon", "cmd_pause",
    ),
    Command(
        "resume", ["unpause", "continue"],
        "/resume",
        "Resume after /pause",
        _ht("  /resume"),
        "recon", "cmd_resume",
    ),
    Command(
        "stop", ["abort", "cancel"],
        "/stop",
        "Hard-stop scan: kill dnsx/httpx/nuclei/… immediately",
        _ht(
            "Sets the stop flag and kills in-flight tool process groups",
            "(dnsx, httpx, nuclei, subfinder, …) plus known-tool pkill fallback",
            "so orphans from a prior Ctrl+C are cleaned up too.",
            "Ctrl+C during /run or /agent now hard-stops the same way.",
            "",
            "  /stop",
            "  /jobs",
            "",
            "If a tool ignores SIGTERM, a SIGKILL follows shortly.",
        ),
        "recon", "cmd_stop",
    ),
    Command(
        "jobs", ["job"],
        "/jobs [list|status <id>]",
        "Background recon jobs (/run default)",
        _ht(
            "Examples:",
            "  /run example.com --modules subdomains",
            "  /jobs",
            "  /pause  /resume  /stop",
        ),
        "recon", "cmd_jobs",
    ),
    Command(
        "doctor", ["diag"],
        "/doctor [target]",
        "Self-check: tools, log hints, target output health",
        _ht(
            "Combines env checks, debug.log patterns, and empty-file hints.",
            "",
            "Examples:",
            "  /doctor",
            "  /doctor example.com",
        ),
        "setup", "cmd_doctor", max_args=1,
    ),
    Command(
        "tips", ["rag", "notes"],
        "/tips <query>",
        "Search local bug_bounty_tips.md (and ~/.reconkit/notes)",
        _ht(
            "Lightweight keyword RAG — no external services.",
            "",
            "Examples:",
            "  /tips subdomain takeover",
            "  /tips jwt secrets in javascript",
        ),
        "agents", "cmd_tips", min_args=1,
    ),
    Command(
        "critic", ["review"],
        "/critic [target]",
        "LLM second-pass review of agent_report.md or report_draft.md",
        _ht(
            "Requires working LLM (/check-llm). Detection-only advice.",
            "",
            "Examples:",
            "  /critic example.com",
            "  /critic",
        ),
        "agents", "cmd_critic", max_args=1,
    ),
    Command(
        "rate", ["polite"],
        "/rate [show|stealth|normal|aggressive]",
        "Session politeness profile (advisory + env hints for tools)",
        _ht(
            "Profiles:",
            "  stealth     lower concurrency hints",
            "  normal      default",
            "  aggressive  faster (use carefully, stay in RoE)",
            "",
            "Examples:",
            "  /rate",
            "  /rate stealth",
            "  /rate normal",
        ),
        "shell", "cmd_rate", max_args=1,
    ),
    # --- v2.1.0 safe validation / prove ---
    Command(
        "prove", ["validate", "proof"],
        "/prove <policy|techniques|queue|run|list|show> …",
        "Safe validation of recon findings (no destructive exploits)",
        _ht(
            "SAFE MODE ONLY — marker/canary rechecks, no sqlmap/shells/dumps.",
            "Builds a queue from the findings index (notable by default).",
            "",
            "Subcommands:",
            "  policy                 show config/exploit_policy.json",
            "  techniques             list safe validators",
            "  queue [target]         preview what would be validated",
            "  run [target]           run validators (scope required)",
            "  list [target]          list saved proofs",
            "  show <id>              show one proof (needs /target)",
            "",
            "Examples:",
            "  /prove policy",
            "  /prove techniques",
            "  /prove queue",
            "  /prove queue example.com",
            "  /prove run example.com",
            "  /prove run example.com --technique xss_reflect --dry-run",
            "  /prove list example.com",
            "",
            "CLI: python recon_prove.py run --target example.com",
            "Policy: config/exploit_policy.json",
        ),
        "recon", "cmd_prove", min_args=1,
        subcommands=["policy", "techniques", "queue", "run", "list", "show"],
        flags=["--technique", "--limit", "--all", "--dry-run"],
    ),
    Command(
        "program", ["prog", "bb"],
        "/program <list|show|set> [name]",
        "Bug bounty program profile (score weights / RoE hints)",
        _ht(
            "Profiles live in config/programs/*.json and weight /notable scores.",
            "",
            "Examples:",
            "  /program list",
            "  /program show",
            "  /program set example-web",
            "  /program set default",
            "",
            "Env: RECON_PROGRAM=example-web",
            "After set: /findings reindex so scores refresh.",
        ),
        "recon", "cmd_program", min_args=1,
        subcommands=["list", "show", "set"],
    ),
    Command(
        "graph", ["paths", "attackgraph"],
        "/graph [summary|show] [target]",
        "Attack-path relationship graph (nodes/edges from findings+proofs)",
        _ht(
            "Builds target→host→finding→proof relations for the dashboard Graph tab.",
            "",
            "Examples:",
            "  /graph",
            "  /graph summary",
            "  /graph show example.com",
            "",
            "UI: open /dashboard → Graph tab",
            "API: GET /api/graph?target=example.com",
        ),
        "recon", "cmd_graph",
    ),
]


def _normalize(token: str) -> str:
    t = token.strip().lower()
    if t.startswith("/"):
        t = t[1:]
    return t


def build_lookup() -> dict[str, Command]:
    table: dict[str, Command] = {}
    for cmd in COMMANDS:
        table[cmd.name] = cmd
        for a in cmd.aliases:
            table[a] = cmd
    return table


LOOKUP = build_lookup()


def _attach_subcommands() -> None:
    """Populate subcommands/flags on each Command from the maps above."""
    for c in COMMANDS:
        if c.subcommands is None:
            c.subcommands = list(_SUBCOMMAND_MAP.get(c.name, []))
        if c.flags is None:
            c.flags = list(_FLAG_MAP.get(c.name, []))


_attach_subcommands()


def resolve(token: str) -> Command | None:
    return LOOKUP.get(_normalize(token))


def all_slash_names() -> list[str]:
    names = sorted({c.name for c in COMMANDS})
    return [f"/{n}" for n in names]


def all_command_names() -> list[str]:
    """Canonical names only (no aliases), registration order."""
    seen: list[str] = []
    for c in COMMANDS:
        if c.name not in seen:
            seen.append(c.name)
    return seen


def categories() -> list[str]:
    seen: list[str] = []
    for c in COMMANDS:
        if c.category not in seen:
            seen.append(c.category)
    return seen


def slash_completions(buffer: str) -> list[str]:
    """
    Completions for the current line buffer (slash UX).

    Contextual — after --modules shows recon modules, after --provider
    shows LLM providers, /keys set shows key names, etc.

    Examples:
      "/"                         → /help, /run, /scope, …
      "/sc"                       → /scan, /scope
      "/scope "                   → add, list, check
      "/run T --modules "         → subdomains, dns, …, all
      "/keys set "                → PDCP_API_KEY, …
      "/config set --provider "   → ollama, xai, …
    """
    try:
        from shell.suggestions import contextual_suggestions
        raw = (buffer or "").lstrip()
        return [ins for ins, _ in contextual_suggestions(raw if raw else "/")]
    except Exception:
        raw = (buffer or "").lstrip()
        if not raw or raw == "/":
            return all_slash_names()
        if raw.startswith("/") and " " not in raw:
            pref = raw[1:].lower()
            return [f"/{c.name}" for c in COMMANDS if c.name.startswith(pref)]
        return []


def format_slash_menu(
    *,
    filter_prefix: str = "",
    color_fn=None,
) -> list[str]:
    """
    Lines for the interactive `/` command palette (commands + subcommands).
    filter_prefix: optional partial command name without leading slash.
    """
    lines: list[str] = []
    pref = filter_prefix.lower().lstrip("/")
    for cat in categories():
        title = CATEGORY_TITLES.get(cat, cat)
        block: list[Command] = []
        for c in COMMANDS:
            if c.category != cat:
                continue
            if pref and not c.name.startswith(pref) and not any(
                a.startswith(pref) for a in c.aliases
            ):
                continue
            # unique by name
            if any(x.name == c.name for x in block):
                continue
            block.append(c)
        if not block:
            continue
        lines.append(f"▸ {title}")
        for c in block:
            lines.append(f"  /{c.name:<14}  {c.summary}")
            subs = c.subcommands or []
            if subs:
                # show as /cmd sub1 | sub2 | sub3
                sub_s = " · ".join(f"/{c.name} {s}" for s in subs)
                lines.append(f"  {'':16}  subs: {sub_s}")
            flags = c.flags or []
            if flags and not subs:
                lines.append(f"  {'':16}  flags: {', '.join(flags)}")
            elif flags and subs:
                # only show flag-like entries not already in subs
                extra = [f for f in flags if f.split()[0] not in subs]
                if extra:
                    lines.append(f"  {'':16}  flags: {', '.join(extra)}")
            # Value-hint for well-known catalogs (live Tab shows full lists)
            if c.name in ("run", "agent"):
                lines.append(
                    f"  {'':16}  --modules values: subdomains dns httpprobe tls "
                    f"crawl js params content xss sqli ssrf_ssti nuclei cloud screenshots all"
                )
            elif c.name == "config":
                lines.append(
                    f"  {'':16}  --provider values: ollama xai anthropic openai google …"
                )
            elif c.name == "prove":
                lines.append(
                    f"  {'':16}  --technique values: xss_reflect ssti_math nuclei_recheck …"
                )
            elif c.name == "keys":
                lines.append(
                    f"  {'':16}  set/remove values: PDCP_API_KEY GITHUB_TOKEN SHODAN_API_KEY …"
                )
            elif c.name == "playbook":
                lines.append(
                    f"  {'':16}  run values: quick full js-deep vuln-pass passive …"
                )
        lines.append("")
    return lines


CATEGORY_TITLES = {
    "shell": "Shell & session",
    "setup": "Environment & install",
    "auth": "Authorization & secrets",
    "recon": "Recon pipeline",
    "agents": "Multi-agent LLM orchestration",
}
