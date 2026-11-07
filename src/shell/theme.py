"""Shell UI for reconkit.

One steel accent, gray metadata, and a plain startup banner.
"""

from __future__ import annotations

import os
import platform

try:
    import reconkit as rk
except Exception:  # pragma: no cover
    rk = None

from shell.fleet_art import (
    CYBER_BANNER,
    CYBER_SCAN_LINES,
)


def _c(text: str, *codes: str) -> str:
    if rk is None:
        return text
    return rk._c(text, *codes)


class SoftShellColors:
    """Dark-terminal palette. Accent names match the color."""

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

    BRIGHT_RED = "\033[38;5;167m"
    BRIGHT_GREEN = "\033[38;5;108m"
    BRIGHT_YELLOW = "\033[38;5;179m"
    BRIGHT_BLUE = "\033[38;5;110m"
    BRIGHT_MAGENTA = "\033[38;5;139m"
    BRIGHT_CYAN = "\033[38;5;73m"

    BOLD_RED = "\033[1;31m"
    BOLD_GREEN = "\033[1;32m"
    BOLD_CYAN = "\033[1;36m"
    BOLD_MAGENTA = "\033[1;35m"

    # Call sites still use these names. The values are a quiet shell palette.
    NEON_CYAN = "\033[38;5;73m"       # steel cyan
    NEON_GREEN = "\033[38;5;108m"     # status green
    NEON_PINK = "\033[38;5;180m"      # warm secondary
    NEON_PURPLE = "\033[38;5;103m"    # slate
    ORANGE = "\033[38;5;179m"         # amber, for warnings

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


SUBTITLE = CYBER_BANNER


def print_banner(version: str = "3.0.0", animate: bool = True) -> None:
    """Startup banner. `animate` is accepted and ignored."""
    del animate
    col = C()
    print()
    print(
        "  "
        + _c("reconkit", col.BOLD, col.NEON_CYAN)
        + _c("  ", col.GRAY)
        + _c(version, col.BOLD, col.BRIGHT_YELLOW)
    )
    print(_c("  " + "-" * 54, col.NEON_CYAN))
    print(_c(f"  {SUBTITLE}", col.GRAY))
    print()
    for cmd, desc in CYBER_SCAN_LINES:
        print(_c("  " + cmd.ljust(16), col.BOLD, col.NEON_CYAN) + _c(desc, col.GRAY))
    print()
    print(
        _c("  " + platform.node(), col.BRIGHT_YELLOW)
        + _c("   " + platform.system().lower(), col.GRAY)
        + _c("   python " + platform.python_version(), col.NEON_GREEN)
    )
    print()


def print_section(title: str) -> None:
    col = C()
    label = title.strip()
    print()
    print(_c(f"  {label}", col.BOLD, col.NEON_CYAN))
    print(_c("  " + "-" * min(48, max(12, len(label))), col.DIM, col.GRAY))


def print_cmd_line(name: str, usage: str, desc: str) -> None:
    col = C()
    print(
        f"  {_c(name.ljust(14), col.BOLD, col.NEON_GREEN)}"
        f" {_c(usage.ljust(36), col.CYAN)}"
        f" {_c(desc, col.GRAY)}"
    )


def make_prompt(target: str, verbose: int, verbose_label: str) -> str:
    """Two-line prompt: tool name, target, verbosity."""
    col = C()
    tgt = target if target else "none"
    tgt_col = col.NEON_GREEN if target else col.GRAY
    return (
        _c("┌─ ", col.NEON_CYAN)
        + _c("reconkit", col.BOLD, col.NEON_CYAN)
        + _c("  ", col.GRAY)
        + _c(tgt, col.BOLD, tgt_col)
        + _c(f"  v{verbose} {verbose_label}", col.GRAY)
        + "\n"
        + _c("└─> ", col.NEON_CYAN)
    )


def clear_screen() -> None:
    os.system("cls" if platform.system() == "Windows" else "clear")
