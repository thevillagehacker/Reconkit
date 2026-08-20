"""Cyberwarfare shell UI for reconkit (v3.0.0).

Red/black ops-console aesthetic.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
import time

try:
    import reconkit as rk
except Exception:  # pragma: no cover
    rk = None

from shell.fleet_art import (
    CYBER_BANNER,
    CYBER_SCAN_LINES,
    MODULE_SHIP_META,
    RECONKIT_WORDMARK,
)


def _c(text: str, *codes: str) -> str:
    if rk is None:
        return text
    return rk._c(text, *codes)


class SoftShellColors:
    """Cyberwarfare palette — red / amber / dim green on black."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"

    BRIGHT_RED = "\033[38;5;196m"
    BRIGHT_GREEN = "\033[38;5;114m"
    BRIGHT_YELLOW = "\033[38;5;214m"
    BRIGHT_BLUE = "\033[38;5;117m"
    BRIGHT_MAGENTA = "\033[38;5;204m"
    BRIGHT_CYAN = "\033[38;5;87m"

    BOLD_RED = "\033[1;31m"
    BOLD_GREEN = "\033[1;32m"
    BOLD_CYAN = "\033[1;36m"
    BOLD_MAGENTA = "\033[1;35m"

    # Accents (kept name-compatible with existing callers)
    NEON_CYAN = "\033[38;5;203m"      # hot red-pink
    NEON_GREEN = "\033[38;5;114m"     # status green
    NEON_PINK = "\033[38;5;210m"      # soft red
    NEON_PURPLE = "\033[38;5;167m"    # deep red
    ORANGE = "\033[38;5;196m"         # primary red

    enabled = True


def C():
    if rk is not None and not getattr(rk.Colors, "enabled", True):
        class _No:
            RESET = BOLD = DIM = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = ""
            WHITE = GRAY = BRIGHT_RED = BRIGHT_GREEN = BRIGHT_YELLOW = ""
            BRIGHT_BLUE = BRIGHT_MAGENTA = BRIGHT_CYAN = ""
            BOLD_RED = BOLD_GREEN = BOLD_CYAN = BOLD_MAGENTA = ""
            NEON_GREEN = NEON_CYAN = NEON_PINK = NEON_PURPLE = ORANGE = ""
            enabled = False

        return _No()
    return SoftShellColors


FLEET = [
    (mod, name, klass)
    for mod, (name, klass) in MODULE_SHIP_META.items()
    if mod not in ("pipeline", "default")
]

SUBTITLE = "AUTHORIZED RECON  ·  DETECTION ONLY  ·  CYBER OPS"


def term_width(default: int = 78) -> int:
    try:
        return max(60, min(shutil.get_terminal_size((default, 24)).columns, 120))
    except Exception:
        return default


def _tty() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _animate_enabled() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("RECONKIT_NO_ANIM") == "1":
        return False
    if not _tty():
        return False
    return True


def _center_block(text: str, width: int | None = None) -> list[str]:
    w = width or term_width()
    out: list[str] = []
    for line in text.splitlines():
        pad = max(0, (w - len(line)) // 2)
        out.append(" " * pad + line)
    return out


def _print_block(text: str, *color_codes, width: int | None = None) -> None:
    col = C()
    codes = color_codes or (col.ORANGE,)
    for line in _center_block(text, width or min(term_width(), 78)):
        print(_c(line, *codes))


def _print_cyber_boot(col, animate: bool = True) -> None:
    """Short boot lines."""
    lines = list(CYBER_SCAN_LINES)
    if animate and _animate_enabled():
        for i, line in enumerate(lines):
            print(_c(line, col.DIM, col.NEON_GREEN if i < 3 else col.BRIGHT_YELLOW))
            sys.stdout.flush()
            time.sleep(0.05)
    else:
        for i, line in enumerate(lines):
            print(_c(line, col.DIM, col.NEON_GREEN if i < 3 else col.BRIGHT_YELLOW))
    print()


def print_banner(version: str = "3.0.0", animate: bool = True) -> None:
    col = C()
    w = term_width()
    bar = "=" * min(w, 78)
    thin = "-" * min(w, 78)
    print()
    print(_c(bar, col.ORANGE))

    # Wordmark
    _print_block(RECONKIT_WORDMARK, col.BOLD, col.ORANGE)
    print(_c(" " * max(0, (min(w, 78) - 28) // 2) + "R E C O N K I T   ·   C Y B E R   O P S", col.DIM, col.GRAY))
    print()

    # Compact frame
    for line in CYBER_BANNER.splitlines():
        if "[//]" in line or "CYBERWARFARE" in line:
            print(_c(line, col.BOLD, col.BRIGHT_RED if hasattr(col, "BRIGHT_RED") else col.ORANGE))
        elif ">_" in line or "SECURE" in line or "STEALTH" in line:
            print(_c(line, col.NEON_GREEN))
        else:
            print(_c(line, col.GRAY))
    print()

    _print_cyber_boot(col, animate=animate)

    print(_c(thin, col.DIM, col.ORANGE))
    print(_c("  > ", col.ORANGE) + _c(SUBTITLE, col.BRIGHT_YELLOW))
    print(
        _c("  > ", col.ORANGE)
        + _c(f"v{version}", col.BOLD, col.NEON_GREEN)
        + _c("  ·  type ", col.GRAY)
        + _c("/", col.BOLD, col.ORANGE)
        + _c(" or ", col.GRAY)
        + _c("/help", col.BOLD, col.ORANGE)
        + _c("  ·  ", col.GRAY)
        + _c("/dashboard", col.BOLD, col.ORANGE)
        + _c(" for ops UI", col.GRAY)
    )
    print(
        _c("  > ", col.ORANGE)
        + _c(
            f"host={platform.node()}  os={platform.system()}  py={platform.python_version()}",
            col.GRAY,
        )
    )
    print(_c(bar, col.ORANGE))

    # Module roster
    print(_c("  MODULE NODES", col.BOLD, col.NEON_PINK))
    row: list[str] = []
    for mod, name, _klass in FLEET:
        short = name.replace("NODE ", "")
        row.append(f"{mod}→{short}")
        if len(row) >= 4:
            print(_c("  · " + "  |  ".join(row), col.BOLD, col.WHITE))
            row = []
    if row:
        print(_c("  · " + "  |  ".join(row), col.BOLD, col.WHITE))
    print(_c(bar, col.ORANGE))
    print()


def print_section(title: str) -> None:
    col = C()
    print()
    print(_c(f"[//] {title.upper()} ", col.BOLD, col.ORANGE) + _c("-" * 36, col.DIM))


def print_cmd_line(name: str, usage: str, desc: str) -> None:
    col = C()
    print(
        f"  {_c(name.ljust(14), col.BOLD, col.NEON_GREEN)}"
        f" {_c(usage.ljust(36), col.CYAN)}"
        f" {_c(desc, col.GRAY)}"
    )


def make_prompt(target: str, verbose: int, verbose_label: str) -> str:
    """Multi-line ANSI prompt — cyber ops style."""
    col = C()
    tgt = target if target else "none"
    tgt_col = col.NEON_GREEN if target else col.ORANGE
    return (
        _c("┌─[", col.ORANGE)
        + _c("OPS", col.BOLD, col.BRIGHT_RED if hasattr(col, "BRIGHT_RED") else col.ORANGE)
        + _c("@", col.GRAY)
        + _c("v3", col.BRIGHT_YELLOW)
        + _c("]", col.ORANGE)
        + _c("─[", col.ORANGE)
        + _c("target:", col.GRAY)
        + _c(tgt, col.BOLD, tgt_col)
        + _c("]", col.ORANGE)
        + _c("─[", col.ORANGE)
        + _c("v:", col.GRAY)
        + _c(f"{verbose}:{verbose_label}", col.NEON_PINK)
        + _c("]", col.ORANGE)
        + "\n"
        + _c("└─", col.ORANGE)
        + _c(">_ ", col.BOLD, col.NEON_GREEN)
    )


def clear_screen() -> None:
    os.system("cls" if platform.system() == "Windows" else "clear")
