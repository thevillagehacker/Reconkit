"""
Interactive REPL for reconkit + recon-agents (v3.0.0).

Features:
  - Colored cyber banner and prompt
  - Slash commands (/help, /run, /scan, …); bare names also work
  - Typing `/` alone lists every command
  - Interactive /scan module picker
  - Verbosity levels 0–3 (live tool streams at 3)
  - Thin wrappers over reconkit + agents CLI (same safety gates)
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
import traceback
from pathlib import Path
from typing import Any

# Ensure project root is importable when launched as python -m shell
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import reconkit as rk  # noqa: E402
from shell import theme  # noqa: E402
from shell.commands import (  # noqa: E402
    CATEGORY_TITLES,
    COMMANDS,
    HELP_FLAGS,
    LOOKUP,
    all_command_names,
    all_slash_names,
    categories,
    format_slash_menu,
    resolve,
    slash_completions,
)
from shell.slash_menu import run_slash_picker  # noqa: E402
from shell.autocomplete import make_prompt_toolkit_session, read_line  # noqa: E402


class ReconShell:
    VERSION = "3.0.0"

    def __init__(
        self,
        *,
        verbose: int = 1,
        target: str = "",
        intro: bool = True,
    ):
        self.target = (target or "").strip()
        self.intro = intro
        self._running = True
        self._dash_thread = None
        rk.set_verbose(verbose)
        try:
            import os
            self.rate_profile = rk._rate_profile()
            os.environ.setdefault("RECON_RATE", self.rate_profile)
        except Exception:
            self.rate_profile = "normal"
        self._pt_session = None
        self._readline = None
        self._completer_matches: list[str] = []
        self._setup_input()

    # ------------------------------------------------------------------ #
    # Input: prompt_toolkit (live autocomplete) > readline > plain
    # ------------------------------------------------------------------ #
    def _setup_input(self) -> None:
        """Prefer prompt_toolkit for Grok-style complete-while-typing on `/`."""
        self._pt_session = make_prompt_toolkit_session()
        if self._pt_session is not None:
            return
        # Fallback: readline / pyreadline3 (Tab only, not live)
        try:
            import readline  # type: ignore
        except ImportError:
            try:
                import pyreadline3 as readline  # type: ignore
            except ImportError:
                self._readline = None
                return
        self._readline = readline
        try:
            readline.set_completer(self._complete)
            readline.set_completer_delims(" \t\n")
            if "libedit" in getattr(readline, "__doc__", "") or sys.platform == "darwin":
                readline.parse_and_bind("bind ^I rl_complete")
            else:
                readline.parse_and_bind("tab: complete")
                # show all matches when ambiguous
                readline.parse_and_bind("set show-all-if-ambiguous on")
                readline.parse_and_bind("set completion-ignore-case on")
        except Exception:
            pass

    def _complete(self, text: str, state: int) -> str | None:
        """Readline Tab completion fallback."""
        if state == 0:
            buf = text
            if self._readline:
                try:
                    buf = self._readline.get_line_buffer()
                except Exception:
                    buf = text
            line = buf if buf is not None else text
            if line.lstrip().startswith("/") or text.startswith("/") or line.strip() in ("", "/"):
                matches = slash_completions(line if line.strip() else "/")
                if text.startswith("/") or (not text and line.strip() in ("", "/")):
                    self._completer_matches = matches
                elif text:
                    self._completer_matches = [
                        m for m in matches
                        if m.startswith(text) or m.lstrip("/").startswith(text.lstrip("/"))
                    ]
                    if not self._completer_matches:
                        self._completer_matches = [
                            m for m in matches if not m.startswith("/") and m.startswith(text)
                        ] or matches
                else:
                    self._completer_matches = matches
            else:
                names = sorted({c.name for c in COMMANDS})
                mods = list(getattr(rk, "ALL_MODULES", []))
                pool = names + mods
                self._completer_matches = [n for n in pool if n.startswith(text)]
                parts = line.split()
                if parts:
                    cmd = resolve(parts[0])
                    if cmd and (cmd.subcommands or cmd.flags):
                        extra = list(cmd.subcommands or [])
                        for f in cmd.flags or []:
                            extra.append(f.split()[0])
                        self._completer_matches = [
                            e for e in extra if e.startswith(text)
                        ] or self._completer_matches
        try:
            return self._completer_matches[state]
        except IndexError:
            return None

    def _read_command_line(self) -> str:
        """Read one command line with best autocomplete available."""
        # Multi-line ANSI prompt for plain input; single-line for prompt_toolkit
        # (dropdown must sit under a one-line prompt or it is invisible).
        prompt = theme.make_prompt(
            self.target,
            rk.VERBOSE,
            rk.VERBOSE_LABELS.get(rk.VERBOSE, "?"),
        )
        return read_line(
            prompt,
            session=self._pt_session,
            target=self.target,
            verbose=rk.VERBOSE,
            vlabel=rk.VERBOSE_LABELS.get(rk.VERBOSE, "?"),
        )

    # ------------------------------------------------------------------ #
    # Main loop
    # ------------------------------------------------------------------ #
    def run(self) -> None:
        rk.load_secrets_env()
        rk.ensure_dirs()
        if self.intro:
            theme.print_banner(self.VERSION)
            self._print_quick_tips()
            # Tell user which autocomplete engine is active
            col = theme.C()
            if self._pt_session is not None:
                print(
                    theme._c("  Autocomplete: ", col.NEON_GREEN)
                    + theme._c("LIVE ✓", col.BOLD, col.NEON_GREEN)
                )
                print(
                    theme._c("    Matches appear ", col.GRAY)
                    + theme._c("above the prompt", col.BOLD, col.NEON_GREEN)
                    + theme._c(" as you type\n", col.GRAY)
                    + theme._c("    Type ", col.GRAY)
                    + theme._c("/", col.BOLD, col.NEON_CYAN)
                    + theme._c(" → all commands\n", col.GRAY)
                    + theme._c("    Keep typing ", col.GRAY)
                    + theme._c("/co", col.BOLD, col.NEON_CYAN)
                    + theme._c(" → /commands  /config\n", col.GRAY)
                    + theme._c("    Type ", col.GRAY)
                    + theme._c("/comm", col.BOLD, col.NEON_CYAN)
                    + theme._c(" → /commands   then Enter to run\n", col.GRAY)
                    + theme._c("    Type ", col.GRAY)
                    + theme._c("/scope ", col.BOLD, col.NEON_CYAN)
                    + theme._c("→ add / list / check\n", col.GRAY)
                    + theme._c(
                        "    Keys: Tab complete · Enter run · Ctrl-Space force menu",
                        col.GRAY,
                    )
                )
            else:
                from shell.autocomplete import autocomplete_status, _LAST_PT_ERROR
                st = autocomplete_status()
                print(
                    theme._c("  Autocomplete: ", col.ORANGE)
                    + theme._c(st, col.BOLD, col.ORANGE)
                )
                print(
                    theme._c(
                        "    Fix live dropdown:\n"
                        "      1) pip install -U prompt_toolkit\n"
                        "      2) Run in Windows Terminal or cmd.exe (not IDE 'Output')\n"
                        "      3) python recon_shell.py\n"
                        "    Fallback: type ",
                        col.GRAY,
                    )
                    + theme._c("/", col.NEON_CYAN)
                    + theme._c(" alone + Enter for full menu", col.GRAY)
                )
                if _LAST_PT_ERROR:
                    print(theme._c(f"    detail: {_LAST_PT_ERROR[:100]}", col.DIM, col.GRAY))
            print()

        # patch_stdout keeps the prompt alive when background jobs print
        _pt_patch = None
        if self._pt_session is not None:
            try:
                from prompt_toolkit.patch_stdout import patch_stdout as _ps

                _pt_patch = _ps(raw=True)
                _pt_patch.__enter__()
            except Exception:
                _pt_patch = None

        try:
            while self._running:
                try:
                    line = self._read_command_line()
                except (EOFError, KeyboardInterrupt):
                    print()
                    rk.info("Interrupted — type /exit to quit, or continue.")
                    try:
                        cont = read_line(
                            theme._c("  leave shell? [y/N] ", theme.C().YELLOW),
                            session=None,  # simple confirm, no completer
                        ).strip().lower()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        break
                    if cont in ("y", "yes"):
                        break
                    continue

                # Ignore empty Enter while a job just finished (avoids stacking prompts)
                if not (line or "").strip():
                    continue

                self._dispatch(line)
        finally:
            if _pt_patch is not None:
                try:
                    _pt_patch.__exit__(None, None, None)
                except Exception:
                    pass

        print(theme._c("  [//] session ended. stay in authorized scope.", theme.C().ORANGE))
        print()

    def _print_quick_tips(self) -> None:
        col = theme.C()
        print(theme._c("  COMMANDS", col.BOLD, col.ORANGE))
        tips = [
            ("/scope add <domain>", "authorize target (required before scans)"),
            ("/target <domain>", "set active target"),
            ("/scan", "module picker"),
            ("/run [target]", "start scan (background by default · --fg to block)"),
            ("/dashboard", "open local findings dashboard"),
            ("/agent [target]", "LLM planner + specialists"),
            ("/pause /stop", "pause or stop the active scan"),
            ("type / …", "live command complete above prompt"),
            ("/<cmd> -h", "help for any command"),
        ]
        for cmd, desc in tips:
            print(
                f"    {theme._c(cmd.ljust(22), col.BOLD, col.NEON_GREEN)}"
                f" {theme._c(desc, col.GRAY)}"
            )
        print()

    # ------------------------------------------------------------------ #
    # Dispatch
    # ------------------------------------------------------------------ #
    def _expand_unique_slash(self, raw: str) -> str:
        """
        Expand unique prefixes so '/comm' becomes '/commands' and actually runs.

        Without this, Enter on a partial match opened a second menu that closed
        with no visible action — looked like a dead shell.
        """
        s = raw.strip()
        if not s.startswith("/") or " " in s:
            return raw
        token = s.lstrip("/")
        if not token or resolve(token):
            return raw
        hits: list = []
        seen: set[str] = set()
        tl = token.lower()
        for c in COMMANDS:
            if c.name in seen:
                continue
            if c.name.startswith(tl) or any(a.startswith(tl) for a in c.aliases):
                seen.add(c.name)
                hits.append(c)
        if len(hits) == 1:
            expanded = f"/{hits[0].name}"
            if expanded != s:
                rk.info(f"expanded {s} → {expanded}")
            return expanded
        return raw

    def _dispatch(self, line: str) -> None:
        # Strip leftover control chars from some terminals
        raw = (line or "").strip().strip("\x00")
        if not raw:
            return

        # Expand /comm → /commands when unambiguous
        raw = self._expand_unique_slash(raw)

        # Bare "/" → interactive Grok-style palette (main + subcommands)
        if raw in ("/", "/?", "\\"):
            self._open_slash_picker("")
            return

        # Ambiguous partial slash: "/co" matches commands+config → menu
        # Unique partial already expanded above and runs normally.
        if raw.startswith("/") and " " not in raw.strip() and len(raw.strip()) > 1:
            token = raw.strip().lstrip("/")
            if resolve(token) is None:
                matches = []
                seen: set[str] = set()
                tl = token.lower()
                for c in COMMANDS:
                    if c.name in seen:
                        continue
                    if c.name.startswith(tl) or any(a.startswith(tl) for a in c.aliases):
                        seen.add(c.name)
                        matches.append(c)
                if len(matches) > 1:
                    rk.info(
                        f"ambiguous /{token} — matches: "
                        + ", ".join(f"/{m.name}" for m in matches[:12])
                    )
                    self._open_slash_picker(token)
                    return
                if len(matches) == 1:
                    raw = f"/{matches[0].name}"
                elif not matches:
                    rk.fail(f"unknown command: /{token}")
                    rk.info("type / for the command list")
                    return

        try:
            parts = shlex.split(raw, posix=(sys.platform != "win32"))
        except ValueError as e:
            rk.fail(f"parse error: {e}")
            return

        if not parts:
            return

        head = parts[0]
        # Allow "help" and "/help"
        cmd = resolve(head)
        if cmd is None:
            # friendly hint if they typed something like /ru
            if head.startswith("/"):
                pref = head.lstrip("/")
                close = [n for n in all_slash_names() if n[1:].startswith(pref[:3] if pref else "")]
                rk.fail(f"unknown command: {head}")
                if close:
                    rk.info("did you mean: " + ", ".join(close[:8]))
                else:
                    rk.info("type / for the full command list (with subcommands)")
            else:
                rk.fail(f"unknown command: {head}  (try /help, /cmd -h, or /)")
            return

        args = parts[1:]

        # Inline help: /agents -h  ·  /run --help  ·  /scope help  ·  /agent -?
        # Checked before min_args so help always works even when args are required.
        if self._args_request_help(args):
            # /help run --help  → help for `run` (not the help command itself)
            if cmd.name == "help":
                non_flags = [
                    a for a in args
                    if a not in HELP_FLAGS and not a.startswith("--help") and not a.startswith("-h=")
                ]
                if non_flags:
                    target = resolve(non_flags[0])
                    if target:
                        self._show_command_help(target)
                        return
                    rk.fail(f"no such command: {non_flags[0]}")
                    rk.info("type / for the full command list, or /help")
                    return
            self._show_command_help(cmd)
            return

        if cmd.min_args and len(args) < cmd.min_args:
            rk.fail(f"{cmd.name}: need at least {cmd.min_args} argument(s)")
            print(theme._c(f"  usage: {cmd.usage}", theme.C().CYAN))
            print(theme._c(f"  tip:   /{cmd.name} -h   for full help", theme.C().GRAY))
            return
        if cmd.max_args is not None and len(args) > cmd.max_args:
            rk.fail(f"{cmd.name}: too many arguments")
            print(theme._c(f"  usage: {cmd.usage}", theme.C().CYAN))
            print(theme._c(f"  tip:   /{cmd.name} -h   for full help", theme.C().GRAY))
            return

        handler = getattr(self, cmd.handler, None)
        if handler is None:
            rk.fail(f"handler missing for {cmd.name}")
            return

        try:
            handler(args)
        except SystemExit as e:
            # argparse inside handlers may call sys.exit — don't kill the shell
            code = e.code if isinstance(e.code, int) else 1
            if code not in (0, None):
                rk.warn(f"command exited with code {code}")
        except KeyboardInterrupt:
            print()
            # Hard-stop: Ctrl+C must kill dnsx/httpx/nuclei, not leave orphans
            try:
                from run_control import CONTROL
                from shell.jobs import JOBS
                n = CONTROL.hard_interrupt()
                job = JOBS.current()
                if job:
                    JOBS.mark_stopping(job.id)
                rk.warn(
                    f"command interrupted (Ctrl+C) — stopped scan"
                    + (f", signaled {n} process group(s)" if n else "")
                )
                print("  /jobs  to confirm · orphan tools force-killed if known")
            except Exception:
                rk.warn("command interrupted")
        except Exception as e:
            # RunStopped bubbles from reconkit as Exception subclass sometimes
            if e.__class__.__name__ == "RunStopped":
                rk.warn(f"stopped: {e}")
                return
            rk.fail(f"{cmd.name} error: {e}")
            if rk.VERBOSE >= rk.VERBOSE_DEBUG:
                traceback.print_exc()

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _args_request_help(args: list[str]) -> bool:
        """True if the user asked for help via -h / --help / -? / help."""
        for a in args:
            if a in HELP_FLAGS:
                return True
            # also accept --help=… style (unlikely but harmless)
            if a.startswith("--help=") or a.startswith("-h="):
                return True
        return False

    def _show_command_help(self, cmd) -> None:
        """Print detailed usage for one registered slash command (all cmds)."""
        col = theme.C()
        theme.print_section(f"/{cmd.name}  —  help")
        print(f"  {theme._c('usage', col.BOLD)}     {theme._c(cmd.usage, col.CYAN)}")
        print(f"  {theme._c('about', col.BOLD)}     {cmd.summary}")
        print(
            f"  {theme._c('category', col.BOLD)}  "
            f"{CATEGORY_TITLES.get(cmd.category, cmd.category)}"
        )
        if cmd.aliases:
            als = ", ".join(f"/{a}" for a in cmd.aliases)
            print(f"  {theme._c('aliases', col.BOLD)}   {theme._c(als, col.GRAY)}")
        print(
            f"  {theme._c('help via', col.BOLD)}  "
            + theme._c(
                f"/{cmd.name} -h  ·  /{cmd.name} --help  ·  /{cmd.name} -?  ·  "
                f"/{cmd.name} help  ·  /help {cmd.name}",
                col.NEON_GREEN,
            )
        )
        if cmd.min_args:
            print(f"  {theme._c('min args', col.BOLD)}  {cmd.min_args}")
        if cmd.max_args is not None:
            print(f"  {theme._c('max args', col.BOLD)}  {cmd.max_args}")
        print()
        print(theme._c("  details", col.BOLD, col.BRIGHT_MAGENTA))
        for line in cmd.help_text.splitlines():
            print(f"    {line}")
        print()
        print(
            theme._c(
                "  Tip: every shell command supports -h / --help the same way "
                f"(try /{all_command_names()[0]} -h, /run -h, /scope -h, …).",
                col.GRAY,
            )
        )
        print(
            theme._c("  ", col.GRAY)
            + theme._c("/help", col.BOLD, col.NEON_CYAN)
            + theme._c(" — full catalog  ·  ", col.GRAY)
            + theme._c("/", col.BOLD, col.NEON_CYAN)
            + theme._c(" — list all names  ·  append ", col.GRAY)
            + theme._c("-h", col.BOLD, col.NEON_GREEN)
            + theme._c(" to any command", col.GRAY)
        )
        print()

    def _require_target(self, args: list[str], pos: int = 0) -> str | None:
        """Pull target from args[pos] or session target."""
        if len(args) > pos and not args[pos].startswith("-"):
            return args[pos].strip()
        if self.target:
            return self.target
        rk.fail("no target set — pass one or use /target <domain>")
        return None

    def _apply_verbose_to_reconkit(self) -> None:
        # already global via rk.set_verbose
        if rk.VERBOSE >= rk.VERBOSE_DEBUG:
            rk._ensure_log_dir()

    def _namespace(self, **kwargs) -> argparse.Namespace:
        return argparse.Namespace(**kwargs)

    # ------------------------------------------------------------------ #
    # Shell commands
    # ------------------------------------------------------------------ #
    def cmd_help(self, args: list[str]) -> None:
        # Strip help flags if someone typed `/help -h` or `/help run --help`
        tokens = [a for a in args if a not in HELP_FLAGS and not a.startswith("--help")]
        if tokens:
            token = tokens[0]
            cmd = resolve(token)
            if not cmd:
                rk.fail(f"no such command: {token}")
                rk.info("type / for the full command list, or /help")
                return
            self._show_command_help(cmd)
            return

        # Full catalog
        col = theme.C()
        theme.print_section(f"reconkit v{self.VERSION} — command reference")
        print(
            theme._c("  Tip: ", col.NEON_PINK)
            + theme._c("type ", col.GRAY)
            + theme._c("/", col.BOLD, col.NEON_CYAN)
            + theme._c(" alone to list commands  ·  Tab completes slash names", col.GRAY)
        )
        print(
            theme._c("  Slash menu: ", col.NEON_PINK)
            + theme._c(
                "type /  (Enter) for commands + subcommands  ·  "
                "Tab completes /scope → add|list|check",
                col.GRAY,
            )
        )
        print(
            theme._c("  Inline help (ALL commands): ", col.NEON_PINK)
            + theme._c(
                "/<cmd> -h | --help | -? | help   "
                "e.g. /run -h  /scope --help  /agent -h  /keys -h  /dashboard -h",
                col.GRAY,
            )
        )
        print(
            theme._c("  Verbosity: ", col.NEON_PINK)
            + theme._c(
                "0=quiet  1=normal  2=debug  3=live (full tool stdout/stderr)",
                col.GRAY,
            )
        )
        for cat in categories():
            title = CATEGORY_TITLES.get(cat, cat)
            print()
            print(theme._c(f"  ▸ {title}", col.BOLD, col.BRIGHT_MAGENTA))
            # unique by name preserving order
            seen: set[str] = set()
            for cmd in COMMANDS:
                if cmd.category != cat or cmd.name in seen:
                    continue
                seen.add(cmd.name)
                theme.print_cmd_line(f"/{cmd.name}", cmd.usage, cmd.summary)
        print()
        print(
            theme._c("  Modules: ", col.BOLD)
            + theme._c(", ".join(rk.ALL_MODULES), col.CYAN)
        )
        print(
            theme._c("  Safety:  ", col.BOLD)
            + theme._c(
                "all scans require /scope membership · detection-only (no exploitation)",
                col.ORANGE,
            )
        )
        print()

    def _open_slash_picker(self, initial_filter: str = "") -> None:
        """Interactive palette: list main + subcommands, filter, pick number/name."""
        col = theme.C()
        picked = run_slash_picker(
            c=theme._c,
            Colors=col,
            initial_filter=initial_filter,
        )
        if not picked:
            rk.info("slash menu closed")
            return
        # Dispatch the chosen command (may include args)
        print(theme._c(f"  running: {picked}", col.NEON_GREEN))
        # Avoid re-entering picker if pick was just "/"
        if picked.strip() in ("/", "/?", "\\"):
            return
        self._dispatch(picked)

    def _print_slash_palette(self, filter_prefix: str = "") -> None:
        """Static listing (also used as fallback). Prefer _open_slash_picker."""
        self._open_slash_picker(filter_prefix)

    def cmd_list_commands(self, _args: list[str]) -> None:
        """
        /commands — print a static full list (always visible output).

        Bare `/` still opens the interactive picker. This avoids the confusion
        where picking /commands from autocomplete re-opened an empty-looking menu.
        """
        col = theme.C()
        theme.print_section("slash commands (main + subcommands)")
        print(
            theme._c(
                "  Tip: type / for interactive picker · type /cmd for live dropdown",
                col.GRAY,
            )
        )
        print()
        lines = format_slash_menu(filter_prefix="")
        for line in lines:
            if line.startswith("▸ "):
                print(theme._c(f"  {line}", col.BOLD, col.BRIGHT_MAGENTA))
            elif "subs:" in line or "flags:" in line:
                print(theme._c(line, col.NEON_CYAN))
            elif line.startswith("  /"):
                print(
                    theme._c(line[:18], col.BOLD, col.NEON_GREEN)
                    + theme._c(line[18:] if len(line) > 18 else "", col.GRAY)
                )
            elif line.strip() == "":
                print()
            else:
                print(line)
        print(
            theme._c("  ", col.GRAY)
            + theme._c("/<cmd> -h", col.NEON_GREEN)
            + theme._c(" for details  ·  ", col.GRAY)
            + theme._c("/", col.NEON_CYAN)
            + theme._c(" interactive picker", col.GRAY)
        )
        print()

    def cmd_banner(self, _args: list[str]) -> None:
        theme.print_banner(self.VERSION)

    def cmd_clear(self, _args: list[str]) -> None:
        theme.clear_screen()

    def cmd_status(self, _args: list[str]) -> None:
        col = theme.C()
        theme.print_section("session status")
        print(f"  {theme._c('version', col.GRAY)}   {self.VERSION}")
        print(
            f"  {theme._c('target', col.GRAY)}    "
            f"{theme._c(self.target or '(none)', col.BOLD, col.NEON_GREEN if self.target else col.ORANGE)}"
        )
        print(
            f"  {theme._c('verbose', col.GRAY)}   "
            f"{rk.VERBOSE} ({rk.VERBOSE_LABELS.get(rk.VERBOSE, '?')})"
        )
        print(f"  {theme._c('base_dir', col.GRAY)}  {rk.BASE_DIR}")
        print(f"  {theme._c('output', col.GRAY)}    {rk.OUTPUT_DIR}")
        print(f"  {theme._c('scope', col.GRAY)}     {rk.SCOPE_FILE}")
        try:
            from hunter.session import summary as sess_summary
            print(f"  {theme._c('auth', col.GRAY)}     {sess_summary()}")
        except Exception:
            pass
        try:
            scope = sorted(rk.load_scope())
            print(f"  {theme._c('in_scope', col.GRAY)}  {len(scope)} target(s)")
            for d in scope[:12]:
                print(f"             {theme._c('•', col.NEON_GREEN)} {d}")
            if len(scope) > 12:
                print(f"             … +{len(scope) - 12} more")
        except Exception as e:
            print(f"  {theme._c('in_scope', col.GRAY)}  (unreadable: {e})")

        try:
            from agents.config import config_summary, load_config
            cfg = load_config()
            print()
            print(theme._c("  LLM / agents", col.BOLD, col.BRIGHT_MAGENTA))
            for line in config_summary(cfg).splitlines():
                print(f"    {line}")
        except Exception as e:
            print(f"  {theme._c('LLM', col.GRAY)}      (not loaded: {e})")

        try:
            import os
            prof = getattr(self, "rate_profile", None) or rk._rate_profile()
            rs = rk.rate_settings()
            print()
            print(theme._c("  Rate / index", col.BOLD, col.BRIGHT_CYAN))
            print(f"    rate       {prof}  (RECON_RATE={os.environ.get('RECON_RATE', '')})")
            print(
                f"    knobs      httpx_threads={rs.get('httpx_threads')}  "
                f"nuclei_rl={rs.get('nuclei_rate')}  host_cap={rs.get('host_cap')}  "
                f"js_cap={rs.get('js_cap')}  delay={rs.get('delay_s')}s"
            )
        except Exception:
            pass
        try:
            from findings.db import DB_PATH, usable
            from findings.indexer import get_or_build_index, output_fingerprint
            fp = output_fingerprint().get("token") or ""
            idx = get_or_build_index(refresh=False)
            sql_ok = usable(fp)
            print(f"    index      {idx.get('finding_count', 0)} records  backend={'sqlite' if sql_ok else 'json'}")
            if sql_ok:
                print(f"    sqlite     {DB_PATH}")
            from findings.indexer import query_store
            _rows, st = query_store(min_confidence="C1", limit=1, offset=0)
            print(
                f"    C1+        {st.get('total', 0)}  "
                f"notable={st.get('notable_count', 0)}  "
                f"by_conf={st.get('by_confidence') or {}}"
            )
        except Exception as e:
            print(f"    index      (unavailable: {e})")
        print()

    def cmd_verbose(self, args: list[str]) -> None:
        if not args:
            rk.info(
                f"verbose={rk.VERBOSE} ({rk.VERBOSE_LABELS.get(rk.VERBOSE)})  "
                f"— pass 0|1|2|3 or quiet|normal|debug|live"
            )
            return
        try:
            level = rk.set_verbose(args[0])
        except ValueError as e:
            rk.fail(str(e))
            return
        self._apply_verbose_to_reconkit()
        rk.ok(f"verbose set to {level} ({rk.VERBOSE_LABELS[level]})")
        if level >= rk.VERBOSE_LIVE:
            rk.info("LIVE mode: full stdout/stderr of tools will stream to the console")
        elif level >= rk.VERBOSE_DEBUG:
            rk.info(f"DEBUG mode: diagnostics also append to {rk.DEBUG_LOG}")

    def cmd_target(self, args: list[str]) -> None:
        if not args:
            if self.target:
                rk.info(f"active target: {self.target}")
            else:
                rk.info("no active target — use /target <domain>")
            return
        self.target = args[0].strip()
        if rk.in_scope(self.target):
            rk.ok(f"active target → {self.target} (in scope)")
        else:
            rk.warn(
                f"active target → {self.target} — NOT in scope yet. "
                f"Run: /scope add {self.target}"
            )

    def cmd_exit(self, _args: list[str]) -> None:
        self._running = False

    # ------------------------------------------------------------------ #
    # Setup
    # ------------------------------------------------------------------ #
    def cmd_checkenv(self, _args: list[str]) -> None:
        rk.cmd_checkenv(self._namespace())

    def cmd_setup(self, _args: list[str]) -> None:
        rk.cmd_setup(self._namespace())

    def cmd_verify(self, _args: list[str]) -> None:
        rk.cmd_verify(self._namespace())

    def cmd_wordlists(self, _args: list[str]) -> None:
        rk.cmd_wordlists(self._namespace())

    # ------------------------------------------------------------------ #
    # Auth
    # ------------------------------------------------------------------ #
    def cmd_scope(self, args: list[str]) -> None:
        action = args[0].lower()
        if action == "add":
            rest = args[1:]
            yes = any(a in ("--yes", "-y") for a in rest)
            rest = [a for a in rest if a not in ("--yes", "-y")]
            if not rest:
                rk.fail("usage: /scope add <domain> [--yes]")
                return
            rk.cmd_scope(self._namespace(scope_action="add", domain=rest[0], yes=yes))
        elif action == "list":
            rk.cmd_scope(self._namespace(scope_action="list"))
        elif action == "check":
            if len(args) < 2:
                rk.fail("usage: /scope check <domain>")
                return
            rk.cmd_scope(self._namespace(scope_action="check", domain=args[1]))
        else:
            rk.fail("usage: /scope <add|list|check> [domain]")

    def cmd_keys(self, args: list[str]) -> None:
        """
        /keys set <NAME> <value>
        /keys list
        /keys remove <NAME>

        Tolerates a duplicated 'set' (common tab/typo): 
          /keys set set PDCP_API_KEY <token>  → same as /keys set PDCP_API_KEY <token>
        Value may contain spaces (joined from remaining tokens).
        """
        if not args:
            rk.fail("usage: /keys <set|list|remove> …")
            return
        action = args[0].lower()
        if action == "list":
            rk.cmd_keys(self._namespace(keys_action="list"))
            return
        if action == "remove":
            if len(args) < 2:
                rk.fail("usage: /keys remove <NAME>")
                return
            rk.cmd_keys(self._namespace(keys_action="remove", name=args[1]))
            return
        if action != "set":
            rk.fail("usage: /keys <set|list|remove> …")
            rk.info("example:  /keys set PDCP_API_KEY your-token-here")
            return

        # Remaining after 'set'
        rest = list(args[1:])
        # Drop accidental duplicate subcommand tokens: /keys set set NAME val
        while rest and rest[0].lower() in ("set", "list", "remove", "key", "keys"):
            rest = rest[1:]
        if len(rest) < 2:
            rk.fail("usage: /keys set <NAME> <value>")
            rk.info("example:  /keys set PDCP_API_KEY 5e2b59bf-…")
            rk.info("wrong:    /keys set set PDCP_API_KEY …  (extra 'set' — now auto-skipped)")
            return
        name = rest[0].strip()
        value = " ".join(rest[1:]).strip()
        # If user swapped NAME/value by accident (value looks like KEY, name looks like token)
        if (
            name
            and not re.match(r"^[A-Z][A-Z0-9_]*$", name)
            and re.match(r"^[A-Z][A-Z0-9_]*$", rest[1] if len(rest) > 1 else "")
        ):
            # e.g. /keys set abcd… PDCP_API_KEY  → rare; don't auto-swap silently
            pass
        if not re.match(r"^[A-Z][A-Z0-9_]*$", name):
            rk.fail(
                f"invalid key name {name!r} — use UPPER_SNAKE like PDCP_API_KEY "
                f"(not 'set' / 'list')."
            )
            rk.info("correct:  /keys set PDCP_API_KEY <your-token>")
            return
        if not value or value.lower() in ("set", "list", "remove", "/exit", "exit"):
            rk.fail("missing or invalid key value")
            rk.info("correct:  /keys set PDCP_API_KEY <your-token>")
            return
        rk.cmd_keys(self._namespace(keys_action="set", name=name, value=value))

    def cmd_session(self, args: list[str]) -> None:
        action = (args[0].lower() if args else "show")
        if action in ("show", "list", "status"):
            rk.cmd_session(self._namespace(session_action="show"))
            return
        if action == "clear":
            rk.cmd_session(self._namespace(session_action="clear"))
            return
        if action != "set":
            rk.fail("usage: /session [show|set|clear] [--cookie …] [--cookie-b …] [--header …]")
            return
        cookie = cookie_b = ""
        header: list[str] = []
        header_b: list[str] = []
        i = 1
        while i < len(args):
            a = args[i]
            if a == "--cookie" and i + 1 < len(args):
                cookie = args[i + 1]
                i += 2
                continue
            if a.startswith("--cookie=") and not a.startswith("--cookie-b"):
                cookie = a.split("=", 1)[1]
                i += 1
                continue
            if a in ("--cookie-b", "--cookie_b") and i + 1 < len(args):
                cookie_b = args[i + 1]
                i += 2
                continue
            if a.startswith("--cookie-b="):
                cookie_b = a.split("=", 1)[1]
                i += 1
                continue
            if a in ("--header", "-H") and i + 1 < len(args):
                header.append(args[i + 1])
                i += 2
                continue
            if a in ("--header-b", "--header_b") and i + 1 < len(args):
                header_b.append(args[i + 1])
                i += 2
                continue
            i += 1
        rk.cmd_session(self._namespace(
            session_action="set",
            cookie=cookie,
            cookie_b=cookie_b,
            header=header,
            header_b=header_b,
        ))

    def cmd_har(self, args: list[str]) -> None:
        rest = list(args)
        if rest and rest[0].lower() in ("import", "load"):
            rest = rest[1:]
        if not rest:
            rk.fail("usage: /har import <file.har> [target]")
            return
        path = rest[0]
        target = rest[1] if len(rest) > 1 else (self.target or "")
        if not target:
            rk.fail("pass a target or set /target first")
            return
        rk.cmd_har(self._namespace(target=target, file=path))

    def cmd_evidence(self, args: list[str]) -> None:
        target = ""
        finding_id = ""
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("--id", "-i") and i + 1 < len(args):
                finding_id = args[i + 1]
                i += 2
                continue
            if a.startswith("--id="):
                finding_id = a.split("=", 1)[1]
                i += 1
                continue
            if not a.startswith("-") and not target:
                target = a
            i += 1
        target = target or self.target or ""
        if not target:
            rk.fail("usage: /evidence [target] [--id FINDING_ID]")
            return
        rk.cmd_evidence(self._namespace(target=target, finding_id=finding_id))

    def cmd_inbox(self, args: list[str]) -> None:
        from hunter.ops import build_inbox
        target = (args[0] if args else self.target or "").strip() or None
        data = build_inbox(target=target, limit=25)
        col = theme.C()
        theme.print_section(f"hunter inbox  ({data.get('count', 0)})  {data.get('session', '')}")
        items = data.get("items") or []
        if not items:
            rk.info("no C1+ notable findings — run recon + /findings reindex")
            return
        for i, it in enumerate(items, 1):
            tech = it.get("technique") or "manual"
            print(
                f"  {i:2}. [{it.get('confidence') or '?'} {it.get('severity') or '?'}] "
                f"{theme._c(str(it.get('module') or ''), col.CYAN)}  "
                f"{(it.get('title') or '')[:36]}  "
                f"{theme._c((it.get('asset') or '')[:48], col.GRAY)}  "
                f"→ {tech}"
            )

    def cmd_wordlist_target(self, args: list[str]) -> None:
        target = (args[0] if args else self.target or "").strip()
        if not target:
            rk.fail("usage: /wordlist-target [target]")
            return
        rk.cmd_wordlist_target(self._namespace(target=target))

    # ------------------------------------------------------------------ #
    # Recon
    # ------------------------------------------------------------------ #
    def cmd_modules(self, _args: list[str]) -> None:
        rk.cmd_modules(self._namespace())

    def cmd_outdir(self, args: list[str]) -> None:
        target = self._require_target(args, 0)
        if not target:
            return
        out = rk.OUTPUT_DIR / target.replace("*", "_")
        col = theme.C()
        print(f"  {theme._c(str(out), col.NEON_CYAN)}")
        if not out.exists():
            rk.warn("directory does not exist yet (run a scan first)")
            return
        files = sorted(p for p in out.rglob("*") if p.is_file())
        if not files:
            rk.info("(empty)")
            return
        for p in files[:40]:
            rel = p.relative_to(out)
            size = p.stat().st_size
            print(f"    {theme._c(str(rel), col.GREEN)}  {theme._c(f'{size}B', col.GRAY)}")
        if len(files) > 40:
            print(f"    … +{len(files) - 40} more")

    def _parse_run_args(self, args: list[str]) -> tuple[str | None, str, bool, bool, bool, bool]:
        """Return (target, modules_csv, background, resume, force, scope_all)."""
        target: str | None = None
        modules = "all"
        background = False
        resume = False
        force = False
        scope_all = False
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("--modules", "-m") and i + 1 < len(args):
                modules = args[i + 1]
                i += 2
                continue
            if a.startswith("--modules="):
                modules = a.split("=", 1)[1]
                i += 1
                continue
            if a in ("--bg", "--background", "&"):
                background = True
                i += 1
                continue
            if a in ("--resume",):
                resume = True
                i += 1
                continue
            if a in ("--force",):
                force = True
                i += 1
                continue
            if a in ("--scope-all", "--scope_all"):
                scope_all = True
                i += 1
                continue
            if a.startswith("-"):
                rk.warn(f"unknown flag ignored: {a}")
                i += 1
                continue
            if target is None:
                target = a
            i += 1
        if target is None:
            target = self.target or None
        return target, modules, background, resume, force, scope_all

    def _start_run_job(
        self,
        target: str,
        modules: str,
        *,
        force_fg: bool = False,
        source: str = "run",
        resume: bool = False,
        force: bool = False,
        scope_all: bool = False,
    ) -> None:
        """
        Start a recon run (shared by /run /quick /full /scan /playbook).

        Default is background so /pause /resume /stop work from the same shell.
        Use --fg for blocking foreground. Always seeds live_mission for the dashboard.
        """
        self._apply_verbose_to_reconkit()
        ns = self._namespace(
            target=target,
            modules=modules,
            source=source,
            resume=resume,
            force=force,
            scope_all=scope_all,
        )

        # Eager live tracker seed (before job thread starts) so the UI flips immediately
        if target and not scope_all:
            try:
                from live_mission import start_run
                from pathlib import Path
                mods = (
                    list(rk.ALL_MODULES)
                    if modules.strip().lower() == "all"
                    else [m.strip() for m in modules.split(",") if m.strip()]
                )
                outdir = Path(rk.OUTPUT_DIR) / target.replace("*", "_")
                outdir.mkdir(parents=True, exist_ok=True)
                start_run(target=target, modules=mods, outdir=outdir, source=source)
                print(
                    theme._c(
                        f"  live tracker · source={source} · {len(mods)} phase(s) · {outdir}",
                        theme.C().GRAY,
                    )
                )
            except Exception:
                pass

        if force_fg:
            rk.info("foreground run — Ctrl+C to interrupt ( /pause needs background )")
            rk.cmd_run(ns)
            return

        from shell.jobs import JOBS

        def work():
            rk.cmd_run(ns)
            return f"done {target} modules={modules} source={source}"

        job = JOBS.submit("run", f"{source} {target} [{modules}]", work)
        rk.ok(f"scan job {job.id} started in background ({source})")
        print("  controls:  /pause   /resume   /stop   /jobs")
        print("  tip:       /outdir " + target + "  ·  /dashboard for live phase tiles")

    def cmd_run(self, args: list[str]) -> None:
        target, modules, background, resume, force, scope_all = self._parse_run_args(args)
        if not target and not scope_all:
            rk.fail("usage: /run [target] [--modules a,b,c|all] [--bg|--fg] [--resume] [--scope-all]")
            return
        # --bg is default now; --fg forces foreground
        force_fg = any(a in ("--fg", "--foreground") for a in args)
        # explicit --bg still background; no flag → background (for pause/stop)
        self._start_run_job(
            target or "",
            modules,
            force_fg=force_fg,
            source="run",
            resume=resume,
            force=force,
            scope_all=scope_all,
        )

    def cmd_quick(self, args: list[str]) -> None:
        target = self._require_target(args, 0)
        if not target:
            return
        self._start_run_job(
            target, "subdomains,dns,httpprobe", source="quick"
        )

    def cmd_full(self, args: list[str]) -> None:
        target = self._require_target(args, 0)
        if not target:
            return
        self._start_run_job(target, "all", source="full")

    def cmd_pause(self, _args: list[str]) -> None:
        """Pause the active background scan between stages / host iterations."""
        from run_control import CONTROL
        from shell.jobs import JOBS

        job = JOBS.current()
        if not job or job.status not in ("running", "pending"):
            # Still honor CONTROL even if job bookkeeping drifted
            if CONTROL.status() == "running" and not job:
                CONTROL.pause()
                rk.ok("paused active scan (job registry empty — control flag set)")
                print("  /resume to continue  ·  /stop to abort")
                return
            rk.warn("no running scan job — start with /run (background by default)")
            return
        CONTROL.pause()
        job.status = "paused"
        rk.ok(f"paused job {job.id} ({job.label})")
        print("  /resume to continue  ·  /stop to abort  ·  /outdir <target> to inspect")

    def cmd_resume(self, _args: list[str]) -> None:
        from run_control import CONTROL
        from shell.jobs import JOBS

        job = JOBS.current()
        if not job or job.status not in ("paused", "running", "stopping"):
            if not CONTROL.is_paused():
                rk.warn("nothing paused")
                return
        CONTROL.resume()
        if job and job.status == "paused":
            job.status = "running"
            rk.ok(f"resumed job {job.id}")
        else:
            rk.ok("resumed")

    def cmd_stop(self, _args: list[str]) -> None:
        """Stop the active scan — kill in-flight tools (nuclei/httpx/dnsx/…) immediately."""
        from run_control import CONTROL
        from shell.jobs import JOBS

        job = JOBS.current()
        # Mark stopping (still tracked) — do NOT set status=stopped until thread exits
        if job:
            JOBS.mark_stopping(job.id)

        registered = CONTROL.registered_count()
        n_killed = CONTROL.stop()  # flag + registered Popen + known-tool pkill

        # Also stop active HUD spinners so "dnsx-records running…" freezes cleanly
        try:
            from progress_ui import _stop_active_hud
            _stop_active_hud(silent=True)
        except Exception:
            pass

        if job:
            rk.ok(f"stop requested for job {job.id} ({job.label})")
        else:
            rk.ok("stop requested (no background job bookkeeping — tools still killed)")

        if n_killed:
            print(
                f"  killed/signaled {n_killed} process group(s) "
                f"(registered={registered} · plus known-tool fallback)"
            )
        else:
            print(
                "  no matching tool processes found "
                "(already exited, or not a reconkit-spawned tool)"
            )
        print("  /jobs  to confirm status")
        print("  tip: Ctrl+C during /run or /agent also hard-stops tools now")

    def cmd_scan(self, args: list[str]) -> None:
        """Interactive module picker."""
        col = theme.C()
        target = self._require_target(args, 0)
        if not target:
            return

        modules = list(rk.ALL_MODULES)
        selected = set(modules)  # default: all selected

        theme.print_section(f"scan picker → {target}")
        print(
            theme._c(
                "  Toggle modules with numbers. Commands: a=all  n=none  "
                "d=defaults  Enter/r=run  q=cancel",
                col.GRAY,
            )
        )
        print()

        defaults = {
            "subdomains", "dns", "httpprobe", "tls", "crawl", "js",
            "params", "content", "nuclei", "cloud",
        }

        while True:
            for i, m in enumerate(modules, 1):
                mark = theme._c("[x]", col.NEON_GREEN) if m in selected else theme._c("[ ]", col.GRAY)
                desc = rk.MODULE_DESCRIPTIONS.get(m, "")
                print(
                    f"  {theme._c(str(i).rjust(2), col.CYAN)} {mark} "
                    f"{theme._c(m.ljust(12), col.BOLD, col.NEON_CYAN)} "
                    f"{theme._c(desc[:56], col.GRAY)}"
                )
            print()
            print(
                theme._c("  selected: ", col.GRAY)
                + theme._c(
                    ", ".join(m for m in modules if m in selected) or "(none)",
                    col.NEON_GREEN,
                )
            )
            try:
                choice = input(theme._c("  picker▸ ", col.BOLD, col.NEON_PINK)).strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                rk.warn("scan cancelled")
                return

            if choice in ("", "r", "run", "go"):
                if not selected:
                    rk.fail("select at least one module")
                    continue
                break
            if choice in ("q", "quit", "cancel", "x"):
                rk.warn("scan cancelled")
                return
            if choice in ("a", "all"):
                selected = set(modules)
                continue
            if choice in ("n", "none"):
                selected = set()
                continue
            if choice in ("d", "default", "defaults"):
                selected = {m for m in modules if m in defaults}
                continue

            # numbers / names / comma lists
            tokens = [t.strip() for t in choice.replace(",", " ").split() if t.strip()]
            for tok in tokens:
                if tok.isdigit():
                    idx = int(tok)
                    if 1 <= idx <= len(modules):
                        m = modules[idx - 1]
                        if m in selected:
                            selected.discard(m)
                        else:
                            selected.add(m)
                    else:
                        rk.warn(f"out of range: {tok}")
                elif tok in modules:
                    if tok in selected:
                        selected.discard(tok)
                    else:
                        selected.add(tok)
                else:
                    rk.warn(f"unknown: {tok}")

        ordered = [m for m in modules if m in selected]
        rk.info(f"running modules: {', '.join(ordered)}")
        # Same job path as /run so dashboard live tiles + /pause /stop work
        self._start_run_job(
            target, ",".join(ordered), force_fg=False, source="scan"
        )

    # ------------------------------------------------------------------ #
    # Agents
    # ------------------------------------------------------------------ #
    def cmd_agents(self, _args: list[str]) -> None:
        from agents.main import cmd_agents
        cmd_agents(self._namespace())

    def cmd_check_llm(self, _args: list[str]) -> None:
        from agents.main import cmd_check_llm
        # empty overrides → load from config
        ns = self._namespace(
            config="",
            provider=None,
            model=None,
            base_url=None,
            api_key=None,
            temperature=None,
            timeout=None,
            openai_compat=None,
        )
        cmd_check_llm(ns)

    def cmd_config(self, args: list[str]) -> None:
        from agents.main import cmd_config
        action = args[0].lower()
        rest = args[1:]

        if action == "show":
            as_json = "--json" in rest
            cmd_config(self._namespace(
                config_action="show",
                config="",
                json=as_json,
            ))
            return
        if action == "path":
            cmd_config(self._namespace(config_action="path", config=""))
            return
        if action == "init":
            # parse simple flags (must use --key form)
            path = ""
            repo = False
            base_url = "http://127.0.0.1:11434"
            model = "qwen3:8b"
            provider = "ollama"
            force = False
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--repo":
                    repo = True
                elif a == "--force":
                    force = True
                elif a == "--path" and i + 1 < len(rest):
                    path = rest[i + 1]
                    i += 1
                elif a == "--base-url" and i + 1 < len(rest):
                    base_url = rest[i + 1]
                    i += 1
                elif a == "--model" and i + 1 < len(rest):
                    model = rest[i + 1]
                    i += 1
                elif a == "--provider" and i + 1 < len(rest):
                    provider = rest[i + 1]
                    i += 1
                i += 1
            cmd_config(self._namespace(
                config_action="init",
                path=path,
                repo=repo,
                base_url=base_url,
                model=model,
                provider=provider,
                force=force,
            ))
            return
        if action == "set":
            # Only --flag value form (same as recon_agents.py config set)
            kw: dict[str, Any] = {
                "config_action": "set",
                "config": "",
                "provider": None,
                "model": None,
                "base_url": None,
                "api_key": None,
                "temperature": None,
                "timeout": None,
                "max_steps": None,
                "openai_compat": None,
            }
            i = 0
            saw_flag = False
            while i < len(rest):
                a = rest[i]
                if a.startswith("--") and i + 1 < len(rest):
                    key = a[2:].replace("-", "_")
                    val = rest[i + 1]
                    if key in ("temperature",):
                        kw[key] = float(val)
                        saw_flag = True
                    elif key in ("timeout", "max_steps"):
                        kw[key] = int(val)
                        saw_flag = True
                    elif key in kw:
                        kw[key] = val
                        saw_flag = True
                    i += 2
                    continue
                i += 1
            if not saw_flag:
                rk.fail(
                    "usage: /config set --base-url URL [--model M] [--provider P] …\n"
                    "  example: /config set --base-url http://192.168.1.4:11434\n"
                    "  flags:   --base-url --model --provider --api-key "
                    "--temperature --timeout --max-steps --openai-compat true|false\n"
                    "  (bare keys like 'base_url' without -- are not accepted)"
                )
                print(theme._c("  tip:   /config -h", theme.C().GRAY))
                return
            cmd_config(self._namespace(**kw))
            return

        rk.fail("usage: /config <show|path|init|set> …  (try /config -h)")

    def cmd_agent(self, args: list[str]) -> None:
        from agents.main import cmd_run as agent_run

        target: str | None = None
        modules = ""
        dry_run = False
        skip_analyst = False
        approve = False
        max_steps = None
        debug = rk.VERBOSE >= rk.VERBOSE_DEBUG

        i = 0
        while i < len(args):
            a = args[i]
            if a == "--dry-run":
                dry_run = True
                i += 1
                continue
            if a == "--skip-analyst":
                skip_analyst = True
                i += 1
                continue
            if a in ("--approve", "--hitl"):
                approve = True
                i += 1
                continue
            if a in ("--modules", "-m") and i + 1 < len(args):
                modules = args[i + 1]
                i += 2
                continue
            if a == "--max-steps" and i + 1 < len(args):
                max_steps = int(args[i + 1])
                i += 2
                continue
            if a.startswith("-"):
                rk.warn(f"unknown flag ignored: {a}")
                i += 1
                continue
            if target is None:
                target = a
            i += 1

        if not target:
            target = self.target or None
        if not target:
            rk.fail(
                "usage: /agent [target] [--modules a,b] [--dry-run] "
                "[--max-steps N] [--approve]"
            )
            return

        self._apply_verbose_to_reconkit()
        if approve:
            # Orchestrator reads RECON_AGENT_APPROVE; also pass via run wrapper
            import os
            os.environ["RECON_AGENT_APPROVE"] = "1"

        ns = self._namespace(
            target=target,
            modules=modules,
            dry_run=dry_run,
            skip_analyst=skip_analyst,
            max_steps=max_steps,
            debug=debug,
            config="",
            provider=None,
            model=None,
            base_url=None,
            api_key=None,
            temperature=None,
            timeout=None,
            openai_compat=None,
        )
        # Seed live tracker for the full agent mission (not only tool batches)
        try:
            from live_mission import start_run, mark_stopped, finish_run
            from pathlib import Path
            mods = (
                [m.strip() for m in modules.split(",") if m.strip()]
                if modules
                else list(rk.ALL_MODULES)
            )
            outdir = Path(rk.OUTPUT_DIR) / target.replace("*", "_")
            outdir.mkdir(parents=True, exist_ok=True)
            start_run(target=target, modules=mods, outdir=outdir, source="agent")
            print(
                theme._c(
                    f"  live tracker · source=agent · {len(mods)} phase(s) · dashboard MISSION tab",
                    theme.C().GRAY,
                )
            )
        except Exception:
            pass

        # cmd_run builds orchestrator without approve kw — set env is enough
        try:
            agent_run(ns)
        except KeyboardInterrupt:
            try:
                from run_control import CONTROL
                CONTROL.hard_interrupt()
            except Exception:
                pass
            raise
        finally:
            try:
                from pathlib import Path as _P
                from live_mission import mark_stopped, finish_run
                from run_control import CONTROL
                od = str(_P(rk.OUTPUT_DIR) / target.replace("*", "_"))
                if CONTROL.is_stopped():
                    mark_stopped("agent stopped")
                else:
                    finish_run(ok=True, outdir=od)
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Dashboard / findings
    # ------------------------------------------------------------------ #
    def cmd_findings(self, args: list[str]) -> None:
        from findings.indexer import get_or_build_index, index_all_targets, query_store
        from findings.store import INDEX_FILE

        include_c0 = False
        min_conf = "C1"
        limit = 25
        positional: list[str] = []
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--all":
                include_c0 = True
                min_conf = ""
            elif a in ("--min-confidence", "--min-conf", "--confidence") and i + 1 < len(args):
                min_conf = args[i + 1].upper()
                i += 1
            elif a.startswith("--min-confidence=") or a.startswith("--confidence="):
                min_conf = a.split("=", 1)[1].upper()
            elif a == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1])
                i += 1
            elif not a.startswith("-"):
                positional.append(a)
            i += 1

        action = (positional[0].lower() if positional else "summary")
        if action in ("reindex", "rebuild", "index"):
            rk.info("indexing ~/.reconkit/output → JSON + SQLite …")
            payload = index_all_targets(persist=True)
            rk.ok(
                f"indexed {payload.get('target_count', 0)} target(s), "
                f"{payload.get('finding_count', 0)} finding(s) → {INDEX_FILE}"
            )
            try:
                from findings.db import DB_PATH
                rk.ok(f"sqlite → {DB_PATH}")
            except Exception:
                pass
            return

        target = None
        if action == "summary" and len(positional) > 1:
            target = positional[1]
        elif action not in ("summary", "show", "stat", "stats"):
            target = positional[0]

        kw: dict = {"limit": limit, "offset": 0}
        if target:
            kw["target"] = target
        if not include_c0 and min_conf and min_conf != "ALL":
            kw["min_confidence"] = min_conf if min_conf != "C0" else None
            if kw.get("min_confidence") is None:
                kw.pop("min_confidence", None)

        if target:
            rows, stats = query_store(**kw)
            rk.banner(f"Findings: {target}")
            print(f"  matching: {stats.get('total', len(rows))}  "
                  f"(filter min_confidence={kw.get('min_confidence') or 'all'})")
            print(f"  modules:  {stats.get('by_module') or {}}")
            print(f"  severity: {stats.get('by_severity') or {}}")
            print(f"  conf:     {stats.get('by_confidence') or {}}")
            print(f"  backend:  {stats.get('backend')}")
            show = rows[:limit]
            if show:
                print()
                for f in show:
                    print(
                        f"    [{f.get('confidence') or 'C0'}] [{f.get('severity')}] "
                        f"{f.get('module')}: {f.get('title')} — {(f.get('asset') or '')[:70]}"
                    )
            else:
                rk.warn("no rows — run recon + /findings reindex, or /findings T --all")
            return

        payload = get_or_build_index(refresh=False)
        _rows, st = query_store(min_confidence="C1", limit=1, offset=0)
        rk.banner("Findings index")
        print(f"  generated: {payload.get('generated_at') or '(never — run /findings reindex)'}")
        print(f"  targets:   {payload.get('target_count') or len(payload.get('targets') or {})}")
        print(f"  findings:  {payload.get('finding_count', 0)} total  ·  C1+ {st.get('total', 0)}")
        print(f"  json:      {INDEX_FILE}")
        try:
            from findings.db import DB_PATH, usable
            from findings.indexer import output_fingerprint
            print(f"  sqlite:    {DB_PATH}  ({'current' if usable(output_fingerprint().get('token')) else 'missing/stale'})")
        except Exception:
            pass
        for name, info in sorted((payload.get("targets") or {}).items()):
            print(f"    • {name}: {info.get('finding_count', 0)} findings")

    def cmd_dashboard(self, args: list[str]) -> None:
        host = "127.0.0.1"
        port = 8787
        open_browser = True
        background = False
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--no-browser":
                open_browser = False
            elif a in ("--bg", "--background"):
                background = True
            elif a == "--host" and i + 1 < len(args):
                host = args[i + 1]
                i += 1
            elif a == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
                i += 1
            elif a.isdigit():
                port = int(a)
            i += 1
        browse = f"http://127.0.0.1:{port}/"
        rk.info(
            f"dashboard bind {host}:{port}  → {browse}"
            + ("" if host in ("127.0.0.1", "localhost") else f"  LAN: http://<host-ip>:{port}/")
        )
        from dashboard.server import run_server
        if background:
            if self._dash_thread is not None and self._dash_thread.is_alive():
                rk.warn(f"dashboard already running in background → {browse}")
                return
            import threading
            t = threading.Thread(
                target=run_server,
                kwargs={
                    "host": host,
                    "port": port,
                    "open_browser": open_browser,
                    "refresh": True,
                },
                name="reconkit-dashboard",
                daemon=True,
            )
            self._dash_thread = t
            t.start()
            rk.ok(f"dashboard background → {browse}  (shell stays usable)")
            return
        rk.info("blocking this prompt until Ctrl+C — use /dashboard --bg to keep the shell")
        run_server(host=host, port=port, open_browser=open_browser, refresh=True)

    # ------------------------------------------------------------------ #
    # Tier A/B upgrades
    # ------------------------------------------------------------------ #
    def __init_rate(self):
        if not hasattr(self, "rate_profile"):
            self.rate_profile = "normal"

    def cmd_notable(self, args: list[str]) -> None:
        from findings.indexer import query_store
        from findings.scoring import NOTABLE_THRESHOLD

        target = None
        limit = 25
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1])
                i += 2
                continue
            if not a.startswith("-"):
                target = a
            i += 1
        target = target or self.target or None
        rows, stats = query_store(
            target=target,
            notable=True,
            limit=limit,
            offset=0,
        )
        rk.banner(f"Notable records (score≥{NOTABLE_THRESHOLD})" + (f" — {target}" if target else ""))
        if not rows:
            rk.warn("No notable rows. Run recon + /findings reindex.")
            return
        for f in rows:
            print(
                f"  [{f.get('score')}] [{f.get('confidence') or 'C0'}] {f.get('severity')}  "
                f"{str(f.get('module') or ''):12}  {str(f.get('ftype') or ''):10}  "
                f"{(f.get('asset') or '')[:70]}"
            )
        print(
            f"\n  {len(rows)} shown / {stats.get('total', len(rows))} notable  "
            f"· threshold={NOTABLE_THRESHOLD}  · {stats.get('backend')}"
        )

    def cmd_eval(self, args: list[str]) -> None:
        from agents.eval import evaluate_findings, format_eval_report
        from findings.indexer import query_store

        target = self.target or None
        limit = 15
        use_llm = False
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--llm":
                use_llm = True
            elif a == "--limit" and i + 1 < len(args):
                limit = int(args[i + 1])
                i += 1
            elif a.startswith("--limit="):
                limit = int(a.split("=", 1)[1])
            elif not a.startswith("-"):
                target = a
            i += 1
        rows, stats = query_store(
            target=target or None,
            min_confidence="C1",
            limit=max(limit, 30),
            offset=0,
        )
        if not rows:
            rk.warn("no C1+ findings — run recon + /findings reindex")
            return
        llm = None
        if use_llm:
            try:
                from agents.llm import LLMClient
                llm = LLMClient()
            except Exception as e:
                rk.warn(f"LLM unavailable ({e}); heuristic only")
                use_llm = False
        ev = evaluate_findings(rows, limit=limit, use_llm=use_llm, llm=llm)
        theme.print_section(
            f"eval C0–C4{f' — {target}' if target else ''}  ({stats.get('backend')})"
        )
        print(format_eval_report(ev))

    def cmd_diff(self, args: list[str]) -> None:
        from findings.history import diff_target

        target = (args[0] if args else self.target or "").strip()
        if not target:
            rk.fail("usage: /diff <target>  (or /target first)")
            return
        d = diff_target(target)
        if not d.get("ok"):
            rk.warn(d.get("reason", "diff unavailable"))
            print(f"  snapshots: {d.get('snapshots')}")
            rk.info("Run /findings reindex at least twice after scans.")
            return
        rk.banner(f"Diff {target}")
        print(f"  older: {d.get('older')} @ {d.get('older_at')}")
        print(f"  newer: {d.get('newer')} @ {d.get('newer_at')}")
        print(f"  new={d.get('new_count')}  gone={d.get('gone_count')}  score-changed={d.get('changed_count')}")
        if d.get("new"):
            print("\n  NEW:")
            for r in d["new"][:20]:
                print(f"    + [{r.get('score')}] {r.get('severity')} {r.get('module')} {r.get('asset', '')[:60]}")
        if d.get("gone"):
            print("\n  GONE:")
            for r in d["gone"][:10]:
                print(f"    - {r.get('module')} {r.get('asset', '')[:60]}")

    def cmd_report(self, args: list[str]) -> None:
        from findings.indexer import get_or_build_index
        from findings.report import write_report

        target = None
        all_rows = False
        for a in args:
            if a == "--all":
                all_rows = True
            elif not a.startswith("-"):
                target = a
        target = target or self.target
        if not target:
            rk.fail("usage: /report [target] [--all]")
            return
        idx = get_or_build_index(refresh=False)
        path = write_report(
            target,
            idx.get("findings") or [],
            notable_only=not all_rows,
        )
        rk.ok(f"report draft → {path}")

    def cmd_playbook(self, args: list[str]) -> None:
        from playbooks import list_playbooks, modules_csv, get_playbook

        action = args[0].lower()
        if action in ("list", "ls"):
            rk.banner("Playbooks")
            for p in list_playbooks():
                print(f"  {p['name']:16}  {','.join(p['modules'])}")
                print(f"  {'':16}  {p['description']}")
            return
        if action == "run":
            if len(args) < 2:
                rk.fail("usage: /playbook run <name> [target]")
                return
            name = args[1]
            target = args[2] if len(args) > 2 else self.target
            if not target:
                rk.fail("set /target or pass domain")
                return
            csv = modules_csv(name)
            if not csv:
                rk.fail(f"unknown playbook: {name}. Try /playbook list")
                return
            pb = get_playbook(name)
            rk.info(f"playbook {name}: {pb['description']}")
            self._start_run_job(
                target, csv, force_fg=False, source=f"playbook:{name}"
            )
            return
        rk.fail("usage: /playbook list | /playbook run <name> [target]")

    def cmd_jobs(self, args: list[str]) -> None:
        from shell.jobs import JOBS

        if not args or args[0] in ("list", "ls"):
            jobs = JOBS.list_jobs()
            if not jobs:
                rk.info("no jobs yet — start one with /run … --bg")
                return
            rk.banner("Background jobs")
            for j in jobs[:30]:
                print(
                    f"  {j.id}  {j.status:8}  {j.label}  "
                    f"start={j.started_at or '-'}  end={j.finished_at or '-'}"
                )
                if j.error:
                    print(f"         error: {j.error.splitlines()[0][:100]}")
            return
        if args[0] == "status" and len(args) > 1:
            j = JOBS.get(args[1])
            if not j:
                rk.fail(f"unknown job {args[1]}")
                return
            print(j)
            return
        rk.fail("usage: /jobs [list|status <id>]")

    def cmd_doctor(self, args: list[str]) -> None:
        from agents.doctor import diagnose_log, diagnose_target

        rk.banner("Doctor")
        try:
            rk.cmd_checkenv(self._namespace())
        except Exception as e:
            rk.warn(f"checkenv: {e}")
        print("\n-- debug.log hints --")
        for h in diagnose_log():
            print(f"  {h}")
        target = (args[0] if args else self.target or "").strip()
        if target:
            print(f"\n-- target {target} --")
            info = diagnose_target(target)
            print(f"  outdir: {info['outdir']} exists={info['exists']}")
            if info.get("missing_core"):
                print(f"  missing/empty: {info['missing_core']}")
            for h in info.get("hints") or []:
                print(f"  • {h}")

    def cmd_tips(self, args: list[str]) -> None:
        from agents.rag import search_tips

        q = " ".join(args)
        hits = search_tips(q, limit=5)
        rk.banner(f"Tips: {q}")
        if not hits:
            rk.warn("No local matches. Add notes under ~/.reconkit/notes/ or expand bug_bounty_tips.md")
            return
        for i, h in enumerate(hits, 1):
            print(f"\n[{i}] score={h['score']}  source={h['source']}")
            print(h["text"][:700])
            print("---")

    def cmd_critic(self, args: list[str]) -> None:
        from pathlib import Path
        from agents.critic import review_file
        from agents.llm import LLMClient
        from agents.config import load_config

        target = (args[0] if args else self.target or "").strip()
        if not target:
            rk.fail("usage: /critic [target]")
            return
        out = Path.home() / ".reconkit" / "output" / target.replace("*", "_")
        candidates = [out / "agent_report.md", out / "report_draft.md"]
        path = next((p for p in candidates if p.exists()), None)
        if not path:
            rk.fail(f"No report at {candidates[0]} or report_draft.md — run /agent or /report first")
            return
        rk.info(f"critic reviewing {path} …")
        try:
            text = review_file(path, llm=LLMClient(load_config()), target=target)
        except Exception as e:
            rk.fail(f"critic failed: {e}")
            return
        out_path = out / "critic_review.md"
        out_path.write_text(text, encoding="utf-8")
        print(text[:4000])
        rk.ok(f"saved {out_path}")

    def cmd_rate(self, args: list[str]) -> None:
        import os
        self.__init_rate()
        if not args or args[0] in ("show", "status"):
            rs = rk.rate_settings()
            rk.info(f"rate profile: {self.rate_profile}")
            print(
                f"  httpx_threads={rs.get('httpx_threads')}  katana_depth={rs.get('katana_depth')}  "
                f"nuclei_rl={rs.get('nuclei_rate')}  nuclei_c={rs.get('nuclei_conc')}"
            )
            print(
                f"  host_cap={rs.get('host_cap')}  crawl_hosts={rs.get('crawl_hosts')}  "
                f"js_cap={rs.get('js_cap')}  ffuf_t={rs.get('ffuf_threads')}  "
                f"delay_s={rs.get('delay_s')}"
            )
            return
        prof = args[0].lower()
        profiles = {
            "stealth": {"RECON_RATE": "stealth", "hint": "prefer fewer concurrent tools; pause between stages"},
            "normal": {"RECON_RATE": "normal", "hint": "default toolkit behavior"},
            "aggressive": {"RECON_RATE": "aggressive", "hint": "faster; ensure RoE allows it"},
        }
        if prof not in profiles:
            rk.fail("usage: /rate [show|stealth|normal|aggressive]")
            return
        self.rate_profile = prof
        os.environ["RECON_RATE"] = profiles[prof]["RECON_RATE"]
        try:
            rk.persist_rate_profile(prof)
        except Exception:
            pass
        rk.ok(f"rate → {prof}: {profiles[prof]['hint']}")
        rs = rk.rate_settings()
        print(
            f"  httpx_threads={rs.get('httpx_threads')}  nuclei_rl={rs.get('nuclei_rate')}  "
            f"host_cap={rs.get('host_cap')}  delay_s={rs.get('delay_s')}"
        )

    def cmd_prove(self, args: list[str]) -> None:
        """Safe validation of recon findings (v2.2.0 prove layer)."""
        if not args:
            rk.fail("usage: /prove <policy|techniques|queue|run|list|show> …")
            return
        action = args[0].lower().lstrip("/")
        rest = args[1:]

        if action in ("policy", "pol"):
            from prove.policy import policy_summary

            theme.print_section("prove policy (safe validation only)")
            print(policy_summary())
            return

        if action in ("techniques", "tech", "validators"):
            from prove.validators import list_techniques

            theme.print_section("safe validators")
            for t in list_techniques():
                print(f"  • {t}")
            print(theme._c("  (no sqlmap / RCE / dumps — policy max_risk_class=safe)", theme.C().GRAY))
            return

        if action == "queue":
            from prove.queue import build_queue, queue_summary

            target = self.target
            technique = ""
            limit = None
            all_rows = False
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--all":
                    all_rows = True
                elif a == "--technique" and i + 1 < len(rest):
                    i += 1
                    technique = rest[i]
                elif a.startswith("--technique="):
                    technique = a.split("=", 1)[1]
                elif a == "--limit" and i + 1 < len(rest):
                    i += 1
                    limit = int(rest[i])
                elif a.startswith("--limit="):
                    limit = int(a.split("=", 1)[1])
                elif not a.startswith("-"):
                    target = a
                i += 1
            items = build_queue(
                target=target or None,
                notable_only=not all_rows,
                limit=limit,
                techniques=[technique] if technique else None,
            )
            theme.print_section(f"prove queue{f' — {target}' if target else ''}")
            print(queue_summary(items))
            if not items:
                rk.info("empty — run recon + /findings reindex, or /prove queue --all")
            return

        if action == "run":
            from prove.policy import load_policy
            from prove.queue import build_queue
            from prove.runner import run_proofs, summarize_results

            target = self.target
            technique = ""
            limit = None
            all_rows = False
            dry = False
            i = 0
            while i < len(rest):
                a = rest[i]
                if a == "--all":
                    all_rows = True
                elif a == "--dry-run":
                    dry = True
                elif a == "--technique" and i + 1 < len(rest):
                    i += 1
                    technique = rest[i]
                elif a.startswith("--technique="):
                    technique = a.split("=", 1)[1]
                elif a == "--limit" and i + 1 < len(rest):
                    i += 1
                    limit = int(rest[i])
                elif a.startswith("--limit="):
                    limit = int(a.split("=", 1)[1])
                elif not a.startswith("-"):
                    target = a
                i += 1
            if not target:
                rk.fail("usage: /prove run [target] [--technique T] [--dry-run] [--all]")
                return
            rk.require_scope_or_exit(target)
            pol = load_policy()
            print(theme._c(pol.get("banner") or "SAFE VALIDATION ONLY", theme.C().NEON_PINK))
            items = build_queue(
                target=target,
                notable_only=not all_rows,
                limit=limit,
                techniques=[technique] if technique else None,
            )
            if dry:
                from prove.queue import queue_summary

                print(queue_summary(items))
                rk.info("dry-run — no requests sent")
                return
            if not items:
                rk.fail("empty queue — nothing to prove")
                return

            def _progress(i: int, total: int, p: dict) -> None:
                print(
                    f"  [{i}/{total}] {p.get('status')}: {p.get('technique')} "
                    f"{(p.get('asset') or '')[:55]}"
                )

            results = run_proofs(
                items,
                policy=pol,
                scope_check=rk.in_scope,
                on_progress=_progress,
            )
            print()
            print(summarize_results(results))
            rk.ok(f"proofs → ~/.reconkit/output/{target}/proofs/")
            return

        if action == "list":
            from prove.store import list_all_proof_targets, load_proofs

            target = rest[0] if rest and not rest[0].startswith("-") else self.target
            if not target:
                ts = list_all_proof_targets()
                print("Targets with proofs:", ", ".join(ts) or "(none)")
                return
            proofs = load_proofs(target)
            theme.print_section(f"proofs — {target} ({len(proofs)})")
            for p in proofs[:40]:
                print(
                    f"  {p.get('id')}  [{p.get('status')}]  {p.get('technique')}  "
                    f"{(p.get('title') or '')[:40]}"
                )
            return

        if action == "show":
            from prove.store import load_proofs

            pid = rest[0] if rest else ""
            target = self.target
            if len(rest) >= 2 and not rest[1].startswith("-"):
                # /prove show <id> [target]  or  show target id
                pass
            if not pid:
                rk.fail("usage: /prove show <proof_id>  (set /target first)")
                return
            if not target:
                rk.fail("set /target first")
                return
            for p in load_proofs(target):
                if p.get("id") == pid or (p.get("id") or "").startswith(pid):
                    import json

                    print(json.dumps(p, indent=2))
                    return
            rk.fail(f"proof not found: {pid}")
            return

        rk.fail(f"unknown /prove action: {action}")
        rk.info("try: /prove policy | techniques | queue | run | list | show")

    def cmd_program(self, args: list[str]) -> None:
        from programs.profiles import (
            get_active_profile,
            list_profiles,
            load_profile,
            set_active_program,
        )

        action = (args[0] if args else "show").lower()
        if action in ("list", "ls"):
            theme.print_section("program profiles")
            active = get_active_profile().get("name")
            for p in list_profiles():
                mark = "→" if p.get("name") == active else " "
                print(f"  {mark} {p.get('name'):16}  {p.get('display_name')}")
                if p.get("notes"):
                    print(f"      {p['notes']}")
            return
        if action in ("show", "status", "current"):
            p = get_active_profile()
            theme.print_section(f"active program — {p.get('name')}")
            print(f"  display:     {p.get('display_name')}")
            print(f"  threshold:   {p.get('notable_threshold')}")
            print(f"  max_risk:    {p.get('max_risk_class')}")
            print(f"  weights:     {p.get('bounty_weights')}")
            if p.get("notes"):
                print(f"  notes:       {p.get('notes')}")
            return
        if action == "set":
            if len(args) < 2:
                rk.fail("usage: /program set <name>")
                return
            name = args[1]
            # validate exists
            names = {p["name"] for p in list_profiles()}
            if name not in names and name != "default":
                rk.fail(f"unknown profile: {name}. Try /program list")
                return
            path = set_active_program(name)
            rk.ok(f"active program → {name}  ({path})")
            rk.info("run /findings reindex so scores pick up new weights")
            return
        rk.fail("usage: /program list|show|set <name>")

    def cmd_graph(self, args: list[str]) -> None:
        from graph.builder import build_graph, graph_summary

        action = "summary"
        target = self.target
        min_score = 0
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("summary", "show", "stats"):
                action = "summary" if a != "show" else "show"
            elif a == "--min-score" and i + 1 < len(args):
                i += 1
                min_score = int(args[i])
            elif not a.startswith("-"):
                if a in ("summary", "show"):
                    action = a
                else:
                    target = a
            i += 1
        g = build_graph(target=target or None, min_score=min_score)
        theme.print_section(f"attack graph{f' — {target}' if target else ''}")
        print(graph_summary(g))
        if action == "show":
            print()
            for n in (g.get("nodes") or [])[:25]:
                print(
                    f"  [{n.get('kind'):7}] {n.get('label', '')[:50]}  "
                    f"score={n.get('score')} sev={n.get('severity')}"
                )
            if len(g.get("nodes") or []) > 25:
                print(f"  … +{len(g['nodes']) - 25} nodes")
            print()
            print(theme._c("  Full interactive graph: /dashboard → Graph tab", theme.C().GRAY))
        else:
            print(theme._c("  Tip: /graph show  or open dashboard Graph tab", theme.C().GRAY))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="recon-shell",
        description="Interactive reconkit shell (v3.0.0)",
    )
    parser.add_argument("--target", default="", help="Pre-set active target")
    parser.add_argument(
        "-v", "--verbose", type=int, default=1, choices=[0, 1, 2, 3],
        help="Initial verbosity (0 quiet … 3 live)",
    )
    parser.add_argument("--debug", action="store_true", help="Same as --verbose 2")
    parser.add_argument("--no-banner", action="store_true", help="Skip intro banner")
    args = parser.parse_args(argv)

    verbose = 2 if args.debug else args.verbose
    ReconShell(
        verbose=verbose,
        target=args.target,
        intro=not args.no_banner,
    ).run()


if __name__ == "__main__":
    main()
