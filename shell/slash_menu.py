"""
Interactive slash-command palette (Grok CLI–style).

Triggered when the user types `/` (or a partial `/sco`). Lists main commands
and expands subcommands as selectable rows. Filter by typing; pick by number
or name.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .commands import COMMANDS, CATEGORY_TITLES, categories


@dataclass
class SlashItem:
    """One row in the palette."""

    # Full command string to run or continue, e.g. "/scope add" or "/help"
    invoke: str
    # Display label
    label: str
    # One-line description
    summary: str
    category: str
    # True if this is a subcommand row
    is_sub: bool = False
    # If True, after pick we still need more args (show usage / prompt)
    needs_args: bool = False


def build_slash_items() -> list[SlashItem]:
    """Flatten COMMANDS into main + subcommand rows (registration order by category)."""
    items: list[SlashItem] = []
    seen: set[str] = set()
    for cat in categories():
        for c in COMMANDS:
            if c.category != cat or c.name in seen:
                continue
            seen.add(c.name)
            items.append(
                SlashItem(
                    invoke=f"/{c.name}",
                    label=f"/{c.name}",
                    summary=c.summary,
                    category=cat,
                    is_sub=False,
                    needs_args=bool(c.min_args) or bool(c.subcommands),
                )
            )
            # Expand subcommands as first-class rows
            for sub in c.subcommands or []:
                # skip pure flag-looking entries from sub list that are flags
                # (we still list them — useful for /run --bg)
                inv = f"/{c.name} {sub}"
                items.append(
                    SlashItem(
                        invoke=inv,
                        label=f"  /{c.name} {sub}",
                        summary=f"subcommand of /{c.name}",
                        category=cat,
                        is_sub=True,
                        needs_args=sub not in (
                            "list", "show", "path", "reindex", "summary",
                            "checkenv", "0", "1", "2", "3",
                        ),
                    )
                )
            # Common flags as selectable stubs (optional, keep short)
            for fl in c.flags or []:
                token = fl.split()[0]
                if token in (c.subcommands or []):
                    continue
                if not token.startswith("-"):
                    continue
                inv = f"/{c.name} {token}"
                items.append(
                    SlashItem(
                        invoke=inv,
                        label=f"  /{c.name} {token}",
                        summary=f"flag · {fl}",
                        category=cat,
                        is_sub=True,
                        needs_args=True,
                    )
                )
    return items


def filter_items(items: list[SlashItem], query: str) -> list[SlashItem]:
    q = (query or "").strip().lower().lstrip("/")
    if not q:
        return items
    out: list[SlashItem] = []
    for it in items:
        hay = f"{it.invoke} {it.summary} {it.label}".lower()
        if q in hay or all(part in hay for part in q.split()):
            out.append(it)
    return out


def print_palette(
    items: list[SlashItem],
    *,
    c: Callable,
    Colors: type,
    max_rows: int = 40,
) -> None:
    """Pretty-print numbered palette."""
    print()
    print(c("  ╔══════════════════════════════════════════════════════════════╗", Colors.NEON_CYAN))
    print(
        c("  ║", Colors.NEON_CYAN)
        + c("  /  SLASH MENU  ", Colors.BOLD, Colors.NEON_PINK)
        + c("— commands & subcommands", Colors.GRAY)
        + c("           ║", Colors.NEON_CYAN)
    )
    print(c("  ╚══════════════════════════════════════════════════════════════╝", Colors.NEON_CYAN))
    print(
        c("  filter by typing  ·  pick number or name  ·  ", Colors.GRAY)
        + c("Enter", Colors.NEON_GREEN)
        + c(" empty = close  ·  ", Colors.GRAY)
        + c("?cmd", Colors.NEON_GREEN)
        + c(" = help", Colors.GRAY)
    )
    print()

    if not items:
        print(c("  (no matches)", Colors.YELLOW))
        print()
        return

    shown = items[:max_rows]
    last_cat = ""
    for i, it in enumerate(shown, 1):
        if it.category != last_cat:
            last_cat = it.category
            title = CATEGORY_TITLES.get(it.category, it.category)
            print(c(f"  ▸ {title}", Colors.BOLD, Colors.BRIGHT_MAGENTA))
        num = c(f"  {i:>3}.", Colors.CYAN)
        if it.is_sub:
            lab = c(it.label.ljust(28), Colors.NEON_CYAN)
        else:
            lab = c(it.label.ljust(28), Colors.BOLD, Colors.NEON_GREEN)
        print(f"{num} {lab} {c(it.summary[:48], Colors.GRAY)}")

    if len(items) > max_rows:
        print(c(f"  … +{len(items) - max_rows} more — refine filter", Colors.DIM, Colors.GRAY))
    print()


def run_slash_picker(
    *,
    c: Callable,
    Colors: type,
    initial_filter: str = "",
) -> str | None:
    """
    Interactive slash menu loop.

    Returns a command line to dispatch (e.g. "/scope list"), or None if cancelled.
    May prompt for trailing arguments when the pick needs them.
    """
    all_items = build_slash_items()
    filt = (initial_filter or "").lstrip("/")

    while True:
        filtered = filter_items(all_items, filt)
        print_palette(filtered, c=c, Colors=Colors)

        try:
            prompt = c("  /filter▸ ", Colors.BOLD, Colors.NEON_PINK)
            if filt:
                # show current filter in prompt area
                print(c(f"  current filter: {filt!r}  (clear with -)", Colors.DIM, Colors.GRAY))
            raw = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        if raw == "":
            return None
        if raw in ("q", "quit", "exit", "cancel"):
            return None
        if raw == "-":
            filt = ""
            continue
        if raw.startswith("?"):
            # help for a name
            name = raw[1:].strip().lstrip("/")
            return f"/help {name}" if name else "/help"

        # number pick
        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= len(filtered[:40]):
                picked = filtered[idx - 1]
                # Parent with subcommands → drill into filter instead of running
                if not picked.is_sub and _has_children(picked.invoke, all_items):
                    filt = picked.invoke.lstrip("/")
                    continue
                return _finalize_pick(picked, c=c, Colors=Colors)
            print(c(f"  out of range: {idx}", Colors.YELLOW))
            continue

        # exact invoke match in filtered
        cand = raw if raw.startswith("/") else f"/{raw}"
        for it in filtered:
            if it.invoke == cand or it.invoke.lstrip("/") == cand.lstrip("/"):
                if not it.is_sub and _has_children(it.invoke, all_items):
                    filt = it.invoke.lstrip("/")
                    break
                return _finalize_pick(it, c=c, Colors=Colors)
        else:
            # If looks like a full command with args, run it directly
            if raw.startswith("/") and " " in raw:
                return raw

            # Otherwise treat as new filter (narrow the list)
            filt = raw.lstrip("/")
            # leaf command with no children → run it
            exact = [
                it for it in all_items
                if it.invoke == f"/{filt}" and not it.is_sub
            ]
            if len(exact) == 1 and not _has_children(exact[0].invoke, all_items):
                return _finalize_pick(exact[0], c=c, Colors=Colors)
            continue
        continue


def _has_children(invoke: str, items: list[SlashItem]) -> bool:
    """True if invoke is a parent with subcommand rows (e.g. /scope)."""
    prefix = invoke.rstrip() + " "
    return any(it.is_sub and it.invoke.startswith(prefix) for it in items)


def _finalize_pick(it: SlashItem, *, c: Callable, Colors: type) -> str:
    """Optionally prompt for remaining args after a palette pick."""
    inv = it.invoke
    # Subcommands that typically need a trailing value
    needs_value = (
        it.invoke.endswith(" add")
        or it.invoke.endswith(" set")
        or it.invoke.endswith(" remove")
        or it.invoke.endswith(" check")
        or it.invoke.endswith(" run")
        or it.invoke.endswith(" status")
        or it.invoke.endswith(" --modules")
        or it.invoke.endswith(" --base-url")
        or it.invoke.endswith(" --model")
        or it.invoke.endswith(" --port")
        or it.invoke.endswith(" --host")
        or it.invoke.endswith(" --limit")
        or it.invoke.endswith(" --max-steps")
        or it.invoke.endswith(" --provider")
        or it.invoke == "/tips"
        or it.invoke == "/target"
        or it.invoke == "/verbose"
        or (not it.is_sub and it.needs_args and it.invoke in (
            "/run", "/agent", "/scan", "/quick", "/full", "/report",
            "/diff", "/notable", "/outdir", "/critic", "/doctor",
        ))
    )

    if not needs_value:
        print(c(f"  → {inv}", Colors.NEON_GREEN))
        return inv

    # Prompt for remainder
    hints = {
        "/scope add": "domain (e.g. example.com)",
        "/scope check": "domain",
        "/keys set": "NAME value",
        "/keys remove": "NAME",
        "/playbook run": "name [target]",
        "/jobs status": "job-id",
        "/config set": "--base-url URL  (or other --flags)",
        "/config init": "--repo --base-url URL --model TAG",
        "/run": "[target] [--modules a,b] [--bg]",
        "/agent": "[target] [--dry-run] [--approve]",
        "/tips": "search query",
        "/target": "domain",
        "/verbose": "0-3 | quiet|normal|debug|live",
        "/dashboard": "[--port N] [--host 0.0.0.0]",
    }
    hint = hints.get(inv, "arguments (or Enter for none / -h for help)")
    try:
        extra = input(c(f"  args for {inv}  ({hint}): ", Colors.CYAN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return inv

    if not extra:
        # for commands that truly need args, open help
        if it.invoke in ("/scope add", "/keys set", "/tips", "/playbook run"):
            return f"{inv.split()[0]} -h" if not it.is_sub else f"/{inv.split()[0].lstrip('/')} -h"
        return inv
    if extra in ("-h", "--help", "help"):
        main = inv.split()[0]
        return f"{main} -h"
    return f"{inv} {extra}".strip()
