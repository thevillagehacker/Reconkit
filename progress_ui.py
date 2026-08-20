"""
Live scan progress for reconkit — spam-proof bars + tool checklist.

Two progress modes (auto-selected):

  live  — exclusive foreground TTY: one short line rewritten with \\r
  log   — background job / shared TTY / pipe: start + rare heartbeats + end
          (NO \\r animation — that races the shell prompt and spams rows)

Root cause of "lots of Hosts (dns) rows" on Linux:
  /run defaults to a background thread. LiveHUD kept doing \\r redraws while
  prompt_toolkit also owned the TTY → each frame became a new line.
  Fake host_total without updates made it look like 0/2112 forever.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterator

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

_R = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_CYAN = "\033[96m"
_YELLOW = "\033[93m"
_MAGENTA = "\033[95m"
_WHITE = "\033[97m"
_GRAY = "\033[90m"
_BLUE = "\033[94m"

_FILL, _PARTIAL, _EMPTY = "█", "▓", "░"
_ANIM_BRAILLE = list("⠋⠙⠹⠼⠴⠦⠧⠇⠏")
_ANIM_BLOCKS = list("█▓▒░▒▓▉▊▋▌▍▎▏▎▍▌▋▊▉")
_THINK_DOTS = ["   ", ".  ", ".. ", "...", ".. ", ".  "]
_VERBS = ("Thinking", "Scanning", "Working", "Probing", "Resolving", "Harvesting")

PHASE_EMOJI = {
    "pipeline": "▶", "subdomains": "◆", "permute": "✧", "dns": "◇",
    "ports": "▣", "httpprobe": "●", "tls": "▣", "wellknown": "▤",
    "crawl": "◎", "js": "◈", "jsintel": "◈", "params": "◇",
    "apis": "⬢", "content": "▤", "bypass403": "▸", "gfextra": "◇",
    "xss": "✦", "sqli": "▦", "ssrf_ssti": "◉", "redirect": "↪",
    "cors": "◌", "graphql": "⬡", "nuclei": "▲",
    "cloud": "○", "takeover_plus": "⚠", "osint": "◎", "gitrecon": "⌥",
    "screenshots": "□", "default": "•", "done": "✔",
    "fail": "✘", "warn": "!",
}
PHASE_TITLE = {
    "subdomains": "SUBDOMAIN ENUM", "permute": "DNS PERMUTE",
    "dns": "DNS RECORDS", "ports": "PORT PROBE",
    "httpprobe": "HTTP PROBE", "tls": "TLS FINGERPRINT",
    "wellknown": "WELL-KNOWN", "crawl": "URL CRAWL", "js": "JAVASCRIPT",
    "jsintel": "JS INTEL", "params": "PARAMETERS", "apis": "API SURFACE",
    "content": "CONTENT DISCOVERY", "bypass403": "403 BYPASS",
    "gfextra": "GF EXTRAS", "xss": "XSS CANARIES", "sqli": "SQLI CANARIES",
    "ssrf_ssti": "SSRF / SSTI", "redirect": "OPEN REDIRECT",
    "cors": "CORS", "graphql": "GRAPHQL", "nuclei": "NUCLEI",
    "cloud": "CLOUD ASSETS", "takeover_plus": "TAKEOVER+",
    "osint": "SCOPED OSINT", "gitrecon": "GIT RECON",
    "screenshots": "SCREENSHOTS",
    "pipeline": "RECON PIPELINE", "default": "PHASE",
}

try:
    from shell.fleet_art import MODULE_SHIP_META as _SHIP_META, ship_lines as _ship_lines
except Exception:  # pragma: no cover
    _SHIP_META = {
        "subdomains": ("Subdomain enum", "passive"),
        "permute": ("DNS permutations", "passive"),
        "dns": ("DNS records", "passive"),
        "ports": ("Port probe", "active"),
        "httpprobe": ("HTTP probe", "active"),
        "tls": ("TLS fingerprint", "active"),
        "wellknown": ("Well-known paths", "discovery"),
        "crawl": ("URL crawl", "discovery"),
        "js": ("JavaScript", "discovery"),
        "jsintel": ("JS intel", "discovery"),
        "params": ("Parameters", "discovery"),
        "apis": ("API surface", "discovery"),
        "content": ("Content discovery", "discovery"),
        "bypass403": ("403 bypass", "detection"),
        "gfextra": ("gf extras", "discovery"),
        "xss": ("XSS canaries", "detection"),
        "sqli": ("SQLi canaries", "detection"),
        "ssrf_ssti": ("SSRF / SSTI", "detection"),
        "redirect": ("Open redirect", "detection"),
        "cors": ("CORS", "detection"),
        "graphql": ("GraphQL", "detection"),
        "nuclei": ("Nuclei templates", "detection"),
        "cloud": ("Cloud assets", "detection"),
        "takeover_plus": ("Takeover extras", "detection"),
        "osint": ("Scoped OSINT", "passive"),
        "gitrecon": ("Git recon", "passive"),
        "screenshots": ("Screenshots", "visual"),
        "pipeline": ("Pipeline", "control"),
        "default": ("Recon", "utility"),
    }

    def _ship_lines(module: str) -> list[str]:
        return []


FLEET_SHIPS: dict[str, tuple[str, str]] = dict(_SHIP_META)

# Back-compat: SHIP_ART as tuple of lines for demos / external imports
SHIP_ART: dict[str, tuple[str, ...]] = {
    k: tuple(_ship_lines(k)) for k in list(FLEET_SHIPS.keys())
}

# ANSI accent per module
_SHIP_COLORS: dict[str, str] = {
    "subdomains": "\033[38;5;80m",
    "dns": "\033[38;5;117m",
    "httpprobe": "\033[38;5;141m",
    "tls": "\033[38;5;183m",
    "crawl": "\033[38;5;212m",
    "js": "\033[38;5;210m",
    "params": "\033[38;5;222m",
    "content": "\033[38;5;214m",
    "xss": "\033[38;5;203m",
    "sqli": "\033[38;5;196m",
    "ssrf_ssti": "\033[38;5;160m",
    "nuclei": "\033[38;5;196m",
    "cloud": "\033[38;5;87m",
    "screenshots": "\033[38;5;114m",
    "pipeline": "\033[38;5;214m",
    "default": "\033[38;5;80m",
}


def fleet_ship_art(phase: str) -> tuple[str, ...]:
    """Optional ASCII art for a module (usually empty)."""
    key = (phase or "default").lower().strip()
    return tuple(_ship_lines(key))


def fleet_ship_color(phase: str) -> str:
    key = (phase or "default").lower().strip()
    return _SHIP_COLORS.get(key, _SHIP_COLORS["default"])


def fleet_ship_line(phase: str, detail: str = "") -> str:
    """One-line phase header for pipeline stages."""
    key = (phase or "default").lower().strip()
    ship, klass = FLEET_SHIPS.get(key, FLEET_SHIPS["default"])
    title = PHASE_TITLE.get(key, key.upper())
    if _color_on():
        ac = fleet_ship_color(key)
        return (
            f"  {_BOLD}{_YELLOW}✦{_R} "
            f"{_BOLD}{_WHITE}{ship}{_R}  {_GRAY}[{klass}]{_R}  "
            f"{ac}{title}{_R}"
        )
    return f"  ✦ {ship}  [{klass}]  {title}"


def print_module_ship_banner(
    phase: str,
    *,
    index: int = 0,
    total: int = 0,
    detail: str = "",
    animate: bool = True,
) -> None:
    """Minimal cyber ops phase line: unit name + phase only."""
    key = (phase or "default").lower().strip()
    ship, _klass = FLEET_SHIPS.get(key, FLEET_SHIPS["default"])
    phase_name = key.replace("_", " ")
    idx = f"  [{index}/{total}]" if total else ""

    with _IO:
        print()
        if _color_on():
            print(
                f"  {_BOLD}{_RED}[//]{_R} "
                f"{_BOLD}{_WHITE}{ship}{_R}"
                f"{_GRAY}{idx}{_R}"
                f"  {_GRAY}|{_R}  "
                f"{fleet_ship_color(key)}{phase_name}{_R}"
            )
        else:
            print(f"  [//] {ship}{idx}  |  {phase_name}")
        sys.stdout.flush()

_IO = threading.RLock()
_STATE_LOCK = threading.Lock()
_STATE: dict = {
    "module_label": "Modules",
    "module_current": 0,
    "module_total": 0,
    "host_label": "Hosts",
    "host_current": 0,
    "host_total": 0,
    "last_item": "",
    "message": "",
    "verb": None,
}
_ACTIVE_HUD: "LiveHUD | ToolChecklist | None" = None
_HUD_LOCK = threading.Lock()
_VT_READY = False


def progress_mode() -> str:
    """
    live — multi-line friendly exclusive TTY (foreground)
    log  — background job: still animates ONE \\r spinner line when TTY
    off  — silent

    Background jobs used to disable all animation (static "running…"), which
    looked broken. We still avoid multi-bar spam in log mode, but a single
    carriage-return spinner is safe and expected by users.
    """
    forced = (os.environ.get("RECONKIT_PROGRESS") or "").strip().lower()
    try:
        tty = bool(sys.stdout.isatty())
    except Exception:
        tty = False
    if forced == "off":
        return "off"
    if not tty:
        return "log"
    if forced in ("live", "log"):
        return forced
    if os.environ.get("RECONKIT_BG") == "1":
        return "log"
    return "live"


def can_animate() -> bool:
    """True when a single-line \\r spinner is allowed (real TTY, not off)."""
    if progress_mode() == "off":
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _ensure_vt() -> None:
    """Enable Windows VT processing so \\r / colors work; colorama is fine too."""
    global _VT_READY
    if _VT_READY:
        return
    _VT_READY = True
    if os.name != "nt":
        return
    try:
        import colorama  # noqa: F401
        return
    except ImportError:
        pass
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _color_on() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _c(*parts: str) -> str:
    if not _color_on():
        return "".join(p for p in parts if not p.startswith("\033"))
    return "".join(parts)


def phase_emoji(name: str) -> str:
    return PHASE_EMOJI.get(name.lower().strip(), PHASE_EMOJI["default"])


def phase_title(name: str) -> str:
    return PHASE_TITLE.get(name.lower().strip(), name.replace("_", " ").upper())


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def anim_block(frame: int, style: str = "thinking") -> str:
    if style == "block":
        ch = _ANIM_BLOCKS[frame % len(_ANIM_BLOCKS)]
    else:
        ch = _ANIM_BRAILLE[frame % len(_ANIM_BRAILLE)]
    if not _color_on():
        return ch
    colors = (_CYAN, _MAGENTA, _RED, _YELLOW)
    return f"{_BOLD}{colors[frame % 4]}{ch}{_R}"


def think_dots(frame: int) -> str:
    return _THINK_DOTS[frame % len(_THINK_DOTS)]


def cyber_bar(pct: float, width: int = 24, color: str = "red") -> str:
    pct = max(0.0, min(100.0, pct))
    filled = int(round((pct / 100.0) * width))
    if filled >= width:
        body = _FILL * width
    elif filled <= 0:
        body = _EMPTY * width
    else:
        body = _FILL * max(0, filled - 1) + _PARTIAL + _EMPTY * (width - filled)
    if not _color_on():
        return f"|{body}|"
    fg = {"blue": _BLUE, "green": _GREEN, "cyan": _CYAN}.get(color, _RED)
    n = min(width, max(0, filled))
    return f"{_GRAY}|{_R}{_BOLD}{fg}{body[:n]}{_R}{_GRAY}{body[n:]}|{_R}"


def _fmt_elapsed(seconds: float) -> str:
    s = int(max(0, seconds))
    m, s = divmod(s, 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _pct(cur: int, tot: int) -> float:
    if tot <= 0:
        return 0.0
    return min(100.0, 100.0 * cur / tot)


def hud_active() -> bool:
    """True while a checklist/HUD owns the scan UI (suppress $ cmd echo, etc.)."""
    with _HUD_LOCK:
        hud = _ACTIVE_HUD
        if hud is None:
            return False
        # Prefer explicit closed flag; fall back to thread alive for LiveHUD
        if getattr(hud, "_closed", False):
            return False
        return True


_LAST_LIVE_HOST_WRITE = 0.0


def update_pipeline_state(
    *,
    module_label: str | None = None,
    module_current: int | None = None,
    module_total: int | None = None,
    host_label: str | None = None,
    host_current: int | None = None,
    host_total: int | None = None,
    last_item: str | None = None,
    message: str | None = None,
    verb: str | None = None,
) -> None:
    global _LAST_LIVE_HOST_WRITE
    with _STATE_LOCK:
        if module_label is not None:
            _STATE["module_label"] = module_label
        if module_current is not None:
            _STATE["module_current"] = max(0, int(module_current))
        if module_total is not None:
            _STATE["module_total"] = max(0, int(module_total))
        if host_label is not None:
            _STATE["host_label"] = host_label
        if host_current is not None:
            _STATE["host_current"] = max(0, int(host_current))
        if host_total is not None:
            _STATE["host_total"] = max(0, int(host_total))
        if last_item is not None:
            _STATE["last_item"] = last_item
        if message is not None:
            _STATE["message"] = message
        if verb is not None:
            _STATE["verb"] = verb
        h_cur = int(_STATE.get("host_current") or 0)
        h_tot = int(_STATE.get("host_total") or 0)
    # Throttled live-mission host telemetry for the dashboard
    if host_current is not None or host_total is not None:
        now = time.time()
        if now - _LAST_LIVE_HOST_WRITE >= 0.8:
            _LAST_LIVE_HOST_WRITE = now
            try:
                from live_mission import set_hosts
                set_hosts(current=h_cur, total=h_tot)
            except Exception:
                pass


def _snap() -> dict:
    with _STATE_LOCK:
        return dict(_STATE)


def _term_cols() -> int:
    try:
        return max(40, min(200, __import__("shutil").get_terminal_size((100, 24)).columns))
    except Exception:
        return 100


def _plain(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _fit(s: str, cols: int | None = None) -> str:
    cols = cols or _term_cols()
    limit = max(20, cols - 1)
    plain = _plain(s)
    if len(plain) <= limit:
        return s
    return plain[: limit - 1] + "…"


def _stop_active_hud(*, silent: bool = True) -> None:
    global _ACTIVE_HUD
    with _HUD_LOCK:
        hud = _ACTIVE_HUD
        _ACTIVE_HUD = None
    if hud is None:
        return
    try:
        if silent:
            hud.stop(silent=True)  # type: ignore[call-arg]
        else:
            hud.stop()  # type: ignore[call-arg]
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Log lines
# ---------------------------------------------------------------------------

def scan_log(
    msg: str,
    *,
    level: str = "INF",
    frame: int = 0,
    verbose: int = 1,
    min_level: int = 0,
    anim: bool = True,
) -> None:
    if verbose < min_level:
        return
    hud = None
    with _HUD_LOCK:
        hud = _ACTIVE_HUD
    # Park any live bar line so the log doesn't collide with \\r
    if hud is not None and hasattr(hud, "park"):
        try:
            hud.park()
        except Exception:
            pass

    ts = _ts()
    block = anim_block(frame) if anim else ("·" if not _color_on() else f"{_GRAY}·{_R}")
    lvl = level.upper()[:3]
    if _color_on():
        lc = {
            "INF": _CYAN, "OK": _GREEN, "WRN": _YELLOW,
            "ERR": _RED, "DBG": _MAGENTA, "RUN": _YELLOW,
        }.get(lvl, _WHITE)
        line = f"{_GRAY}[{ts}]{_R} {block} {_GRAY}[{_R}{_BOLD}{lc}{lvl}{_R}{_GRAY}]{_R} {msg}"
    else:
        line = f"[{ts}] {block} [{lvl}] {msg}"
    with _IO:
        # Finish any open \\r bar line first
        sys.stdout.write("\n" if getattr(hud, "_bar_open", False) else "")
        if hud is not None:
            try:
                setattr(hud, "_bar_open", False)
            except Exception:
                pass
        print(line)
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Shared single-line bar writer
# ---------------------------------------------------------------------------

def _truncate_plain(text: str, max_plain: int) -> str:
    """Truncate by visible length (strip ANSI) so the line never wraps."""
    if max_plain < 8:
        max_plain = 8
    plain = _plain(text)
    if len(plain) <= max_plain:
        return text
    # Drop ANSI and hard-cut — safer than partial SGR sequences
    return plain[: max_plain - 1] + "…"


def _write_bar_line(text: str, *, open_cr: bool = True) -> None:
    """
    Write/replace ONE status line with \\r (spinner / elapsed).

    Used for both foreground and background scans when stdout is a TTY.
    Only one physical line — never multi-line cursor math (that caused spam).
    """
    _ensure_vt()
    # Cap well under terminal width so the line cannot wrap (\\r fails on wrap).
    cols = min(100, _term_cols())
    max_plain = max(40, cols - 2)
    fitted = _truncate_plain(text, max_plain)
    with _IO:
        if open_cr and can_animate():
            # Clear line + rewrite. Never emit \\n here.
            # Pad with spaces to wipe longer previous frames.
            plain_len = len(_plain(fitted))
            pad = max(0, max_plain - plain_len)
            sys.stdout.write("\r\033[2K" + fitted + (" " * pad))
            sys.stdout.write("\r" + fitted)  # leave cursor at end of content
        else:
            sys.stdout.write(fitted + "\n")
        sys.stdout.flush()


def _clear_cr_line() -> None:
    """Erase the current \\r status line without printing a permanent row."""
    with _IO:
        if can_animate():
            sys.stdout.write("\r\033[2K")
            sys.stdout.flush()


def _end_bar_line() -> None:
    """Commit past the \\r line (newline) so following prints stay clean."""
    with _IO:
        if can_animate():
            sys.stdout.write("\n")
            sys.stdout.flush()


# ---------------------------------------------------------------------------
# ToolChecklist — ONE progress line per tool (no bar spam)
# ---------------------------------------------------------------------------

@dataclass
class _ToolRow:
    name: str
    status: str = "pending"  # pending | running | done | skip | fail
    value: str = "·"
    detail: str = ""
    index: int = 0  # 1-based position in checklist


class ToolChecklist:
    """
    One row per tool. Progress bar is embedded in the finish line only.

    Example (what you want):

      [15:37:50] ▸ Subdomain enum · hackerone.com  (8 tools)
        … [1/8] subfinder     running…
        ✓ [1/8] subfinder     45   |██░░░░░░░░|  12%  00:00:31
        … [2/8] amass         running…
        ✓ [2/8] amass          0   |████░░░░░░|  25%  00:00:31
        …
        ✔ 7 ok · 1 skip · 00:02:30

    Never prints a free-floating bar row by itself (that caused multi-bar spam).
    """

    def __init__(
        self,
        tools: list[str],
        *,
        title: str = "Tools",
        verbose: int = 1,
        interval: float = 0.12,
    ):
        self.verbose = verbose
        self.interval = interval
        self.title = title
        self.rows = [_ToolRow(name=t, index=i) for i, t in enumerate(tools, 1)]
        self._by_name = {r.name: r for r in self.rows}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._frame = 0
        self._t0 = time.time()
        self._closed = False
        self._bar_open = False
        self._started = False
        self._current_running: str | None = None
        self._anim_lock = threading.Lock()
        self._name_w = max(12, min(14, max((len(t) for t in tools), default=12)))

    def is_alive(self) -> bool:
        # Keep True while checklist is open (even without anim thread) so
        # reconkit suppresses "$ cmd" noise under the tool list.
        return not self._closed and self._started

    def start(self) -> "ToolChecklist":
        global _ACTIVE_HUD
        if self.verbose < 0 or self._closed:
            return self
        _ensure_vt()
        _stop_active_hud(silent=True)
        with _HUD_LOCK:
            _ACTIVE_HUD = self

        update_pipeline_state(
            message=self.title,
            module_label="Tools",
            module_current=0,
            module_total=len(self.rows),
            host_current=0,
            host_total=0,
        )

        ts = _ts()
        n = len(self.rows)
        if _color_on():
            head = (
                f"{_GRAY}[{ts}]{_R}  {_BOLD}{_CYAN}▸{_R}  "
                f"{_BOLD}{self.title}{_R}  {_GRAY}({n} tools){_R}"
            )
        else:
            head = f"[{ts}]  ▸  {self.title}  ({n} tools)"
        with _IO:
            print(head)
            sys.stdout.flush()

        self._started = True
        self._stop.clear()
        self._t0 = time.time()
        self._frame = 0
        # Spinner thread whenever we have a TTY (bg or fg) — single \\r line only
        if can_animate():
            self._thread = threading.Thread(
                target=self._loop_live, name="tool-checklist", daemon=True
            )
            self._thread.start()
        return self

    def park(self) -> None:
        """For external log lines: erase spinner and move to a new line."""
        with self._anim_lock:
            if self._bar_open:
                _clear_cr_line()
                _end_bar_line()
                self._bar_open = False

    def set(
        self,
        name: str,
        *,
        status: str | None = None,
        value: str | int | None = None,
        detail: str = "",
    ) -> None:
        row = self._by_name.get(name)
        if row is None:
            row = _ToolRow(name=name, index=len(self.rows) + 1)
            self.rows.append(row)
            self._by_name[name] = row
            self._name_w = max(self._name_w, min(14, len(name)))
            update_pipeline_state(module_total=len(self.rows))
        if status is not None:
            row.status = status
            if status == "running" and value is None:
                row.value = "…"
            elif status == "pending" and value is None:
                row.value = "·"
            elif status == "skip" and value is None:
                row.value = "skip"
            elif status == "fail" and value is None:
                row.value = "fail"
        if value is not None:
            row.value = str(value)
        if detail:
            row.detail = detail

    def start_tool(self, name: str) -> None:
        try:
            from run_control import CONTROL
            CONTROL.check()
        except Exception as e:
            if e.__class__.__name__ == "RunStopped":
                raise
        try:
            from live_mission import set_tool
            set_tool(name)
        except Exception:
            pass
        with self._anim_lock:
            self.set(name, status="running", value="…")
            self._current_running = name
            self._frame = 0
            if can_animate():
                self._paint_running_unlocked()
            else:
                self._print_result_line(name, temporary_running=True)

    def finish_tool(
        self,
        name: str,
        count: int | str | None = None,
        *,
        ok: bool = True,
        skipped: bool = False,
        detail: str = "",
    ) -> None:
        if skipped:
            self.set(name, status="skip", value="skip", detail=detail)
        elif not ok:
            self.set(name, status="fail", value="fail", detail=detail)
        else:
            val = "0" if count is None else str(count)
            self.set(name, status="done", value=val, detail=detail)
        done = sum(1 for r in self.rows if r.status in ("done", "skip", "fail"))
        update_pipeline_state(module_current=done, module_total=len(self.rows))

        # Stop spinner, erase its line, print ONE permanent result (no ghost rows)
        with self._anim_lock:
            if self._current_running == name:
                self._current_running = None
            if self._bar_open:
                _clear_cr_line()
                self._bar_open = False
            self._print_result_line(name, temporary_running=False)

    def _done_count(self) -> int:
        return sum(1 for r in self.rows if r.status in ("done", "skip", "fail"))

    def _print_result_line(self, name: str, *, temporary_running: bool = False) -> None:
        """
        Permanent tool row. Running snapshot only used for non-TTY.
        Animated TTY path never leaves a permanent "running" row.
        """
        if self.verbose < 0:
            return
        row = self._by_name.get(name)
        if row is None:
            return
        total = max(1, len(self.rows))
        if temporary_running:
            idx = min(total, self._done_count() + 1)
        else:
            idx = max(1, self._done_count())
            idx = min(idx, total)
        pct = _pct(self._done_count() if not temporary_running else max(0, idx - 1), total)
        if not temporary_running:
            pct = _pct(self._done_count(), total)
        elapsed = _fmt_elapsed(time.time() - self._t0)
        nw = self._name_w

        if temporary_running:
            line = f"  …  {idx}/{total}  {name:<{nw}}  running…  {elapsed}"
        else:
            bar = cyber_bar(pct, width=18, color=(
                "green" if row.status == "done" else
                "red" if row.status == "fail" else "blue"
            ))
            icon = {"done": "✓", "skip": "–", "fail": "✗"}.get(row.status, "·")
            val = row.value
            detail = f"  {row.detail}" if row.detail else ""
            if _color_on():
                ic = {
                    "done": _GREEN, "skip": _GRAY, "fail": _RED,
                }.get(row.status, _WHITE)
                line = (
                    f"  {_BOLD}{ic}{icon}{_R}  {_GRAY}{idx}/{total}{_R}  "
                    f"{_BOLD}{_WHITE}{name:<{nw}}{_R}  "
                    f"{ic}{val:>6}{_R}  {bar}  {_BOLD}{pct:3.0f}%{_R}  "
                    f"{_GRAY}{elapsed}{_R}{_GRAY}{detail}{_R}"
                )
            else:
                line = (
                    f"  {icon}  {idx}/{total}  {name:<{nw}}  "
                    f"{val:>6}  {bar}  {pct:3.0f}%  {elapsed}{detail}"
                )

        with _IO:
            print(line)
            sys.stdout.flush()

    def _running_text(self) -> str:
        """Compact spinner line — no progress bar (avoids broken dual bars)."""
        name = self._current_running or "…"
        total = max(1, len(self.rows))
        idx = min(total, self._done_count() + 1)
        elapsed = _fmt_elapsed(time.time() - self._t0)
        spin = anim_block(self._frame)
        nw = self._name_w
        try:
            from run_control import CONTROL
            paused = CONTROL.is_paused()
        except Exception:
            paused = False
        tag = "paused" if paused else "running"
        dots = think_dots(self._frame // 2)
        if _color_on():
            return (
                f"  {spin}  {_GRAY}{idx}/{total}{_R}  "
                f"{_BOLD}{_WHITE}{name:<{nw}}{_R}  "
                f"{_YELLOW}{tag}{dots}{_R}  {_GRAY}{elapsed}{_R}"
            )
        return f"  {spin}  {idx}/{total}  {name:<{nw}}  {tag}{dots}  {elapsed}"

    def _paint_running_unlocked(self) -> None:
        if not self._current_running or not can_animate():
            return
        # _write_bar_line takes _IO; we're under _anim_lock already
        text = self._running_text()
        _ensure_vt()
        cols = min(100, _term_cols())
        max_plain = max(40, cols - 2)
        fitted = _truncate_plain(text, max_plain)
        plain_len = len(_plain(fitted))
        pad = max(0, max_plain - plain_len)
        with _IO:
            sys.stdout.write("\r\033[2K" + fitted + (" " * pad))
            sys.stdout.flush()
        self._bar_open = True

    def _paint_running(self) -> None:
        with self._anim_lock:
            self._paint_running_unlocked()

    def _loop_live(self) -> None:
        """Single-line \\r spinner + elapsed for the current tool (bg or fg)."""
        while not self._stop.is_set():
            if self._current_running:
                self._frame += 1
                self._paint_running()
            self._stop.wait(self.interval)

    def stop(self, final_msg: str = "", *, silent: bool = False, level: str = "OK") -> None:
        global _ACTIVE_HUD
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        with self._anim_lock:
            self._current_running = None
            if self._bar_open:
                _clear_cr_line()
                self._bar_open = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self._thread = None

        if silent:
            with _HUD_LOCK:
                if _ACTIVE_HUD is self:
                    _ACTIVE_HUD = None
            return

        if final_msg:
            self.title = final_msg
        done_n = sum(1 for r in self.rows if r.status == "done")
        skipped = sum(1 for r in self.rows if r.status == "skip")
        failed = sum(1 for r in self.rows if r.status == "fail")
        total = len(self.rows)
        elapsed = _fmt_elapsed(time.time() - self._t0)
        p = _pct(done_n + skipped + failed, max(1, total))
        bar = cyber_bar(p, width=20, color="green" if failed == 0 else "red")
        summary = f"{done_n} ok"
        if skipped:
            summary += f" · {skipped} skip"
        if failed:
            summary += f" · {failed} fail"
        with _IO:
            if _color_on():
                print(
                    f"  {_BOLD}{_GREEN}✔{_R}  {bar}  {_BOLD}{total}/{total}{_R} tools  "
                    f"{p:3.0f}%  {summary}  {_GRAY}{elapsed}{_R}"
                )
            else:
                print(f"  ✔  {bar}  {total}/{total} tools  {p:3.0f}%  {summary}  {elapsed}")
            sys.stdout.flush()
        scan_log(
            f"{self.title}  ·  {summary}  ({elapsed})",
            level="OK" if level == "OK" else "ERR",
            verbose=self.verbose,
            anim=False,
        )
        update_pipeline_state(
            module_current=total,
            module_total=total,
        )
        with _HUD_LOCK:
            if _ACTIVE_HUD is self:
                _ACTIVE_HUD = None
        self._bar_open = False
        self._started = False

    def __enter__(self) -> "ToolChecklist":
        return self.start()

    def __exit__(self, *exc) -> None:
        if exc[0] is not None:
            self.stop(level="ERR")
        else:
            self.stop(level="OK")


def tool_checklist(
    tools: list[str],
    *,
    title: str = "Tools",
    verbose: int = 1,
) -> ToolChecklist:
    cl = ToolChecklist(tools, title=title, verbose=verbose)
    cl.start()
    return cl


# ---------------------------------------------------------------------------
# LiveHUD — activity status (live \\r OR quiet log — never both spam)
# ---------------------------------------------------------------------------

class LiveHUD:
    """
    Progress for a long-running step (dnsx, httpx, …).

    Exactly two status lines in log/bg mode:
      … message  running…
      ✓ |████████| 100%  message  00:01:30

    live/fg mode may also animate a single \\r spinner between them.
    """

    def __init__(self, message: str = "", *, verbose: int = 1, interval: float = 0.15):
        self.verbose = verbose
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._frame = 0
        self._t0 = time.time()
        self._message = message
        self._bar_open = False
        self._closed = False
        self._mode = progress_mode()
        self._last_heartbeat = 0.0
        update_pipeline_state(message=message)

    def is_alive(self) -> bool:
        return not self._closed

    def start(self) -> "LiveHUD":
        global _ACTIVE_HUD
        if self.verbose < 0:
            return self
        _ensure_vt()
        _stop_active_hud(silent=True)
        with _HUD_LOCK:
            _ACTIVE_HUD = self
        self._mode = progress_mode()
        self._stop.clear()
        self._t0 = time.time()
        self._frame = 0
        self._last_heartbeat = time.time()

        if self._mode == "off":
            return self

        msg = self._message or "scanning…"
        if can_animate():
            # Live spinner thread owns the status line (no static frozen line)
            self._thread = threading.Thread(target=self._loop_live, name="live-hud", daemon=True)
            self._thread.start()
            self._paint()
            return self

        # Non-TTY: static start line + rare heartbeats
        if _color_on():
            line = f"  {_YELLOW}…{_R} {_BOLD}{_WHITE}{msg}{_R}  {_GRAY}running…{_R}"
        else:
            line = f"  … {msg}  running…"
        with _IO:
            print(line)
            sys.stdout.flush()
        self._thread = threading.Thread(target=self._loop_log, name="live-hud-log", daemon=True)
        self._thread.start()
        return self

    def park(self) -> None:
        if self._bar_open:
            _end_bar_line()
            self._bar_open = False

    def _status_word(self) -> str:
        st = _snap()
        base = st.get("verb") or _VERBS[(self._frame // 10) % len(_VERBS)]
        return str(base) + think_dots(self._frame // 2)

    def _build_line(self, *, final: bool = False) -> str:
        """Keep this SHORT — must never wrap (wrap + \\r = spam rows)."""
        st = _snap()
        elapsed = _fmt_elapsed(time.time() - self._t0)
        spin = "✓" if final else anim_block(self._frame, "thinking")
        msg = st.get("message") or self._message or "scanning…"
        # Trim message so bar stays on one physical line
        msg_short = msg if len(_plain(msg)) <= 36 else (_plain(msg)[:33] + "…")

        htot = int(st["host_total"])
        mtot = int(st["module_total"])
        if htot > 0:
            cur, tot = int(st["host_current"]), htot
            color = "green"
        elif mtot > 0:
            cur, tot = int(st["module_current"]), mtot
            color = "blue"
        else:
            cur, tot = 0, 0
            color = "red"

        if tot > 0:
            p = 100.0 if final else _pct(cur, tot)
            bar = cyber_bar(p, width=16, color=color)
            counts = f"{cur}/{tot}"
            if _color_on():
                return (
                    f"  {spin} {bar} {_BOLD}{counts}{_R} "
                    f"{p:4.0f}% {msg_short} {_GRAY}{elapsed}{_R}"
                )
            return f"  {spin} {bar} {counts} {p:4.0f}% {msg_short} {elapsed}"

        # No totals — spinner + message only (external tools like dnsx)
        if _color_on():
            word = "Done" if final else self._status_word()
            return (
                f"  {spin} {_BOLD}{_CYAN}{word}{_R} {msg_short} {_GRAY}{elapsed}{_R}"
            )
        return f"  {spin} {'Done' if final else '…'} {msg_short} {elapsed}"

    def _paint(self, *, final: bool = False) -> None:
        if self.verbose < 0 or self._mode == "off":
            return
        if can_animate() and not final:
            _write_bar_line(self._build_line(final=False), open_cr=True)
            self._bar_open = True
            return
        self.park()
        with _IO:
            print(self._build_line(final=final))
            sys.stdout.flush()
        self._bar_open = False

    def _loop_live(self) -> None:
        """Single-line \\r spinner for long external tools (dnsx/httpx/nuclei…)."""
        while not self._stop.is_set():
            try:
                from run_control import CONTROL
                if CONTROL.is_paused():
                    self._frame += 1
                    text = self._build_line() + (
                        " [PAUSED]" if not _color_on() else f" {_YELLOW}[PAUSED]{_R}"
                    )
                    _write_bar_line(text, open_cr=True)
                    self._bar_open = True
                    self._stop.wait(0.3)
                    continue
            except Exception:
                pass
            self._frame += 1
            self._paint()
            self._stop.wait(self.interval)

    def _loop_log(self) -> None:
        """Background-safe: rare heartbeats as normal log lines (no \\r)."""
        while not self._stop.is_set():
            self._stop.wait(5.0)
            if self._stop.is_set():
                break
            now = time.time()
            if now - self._last_heartbeat < 15.0:
                continue
            self._last_heartbeat = now
            elapsed = _fmt_elapsed(now - self._t0)
            st = _snap()
            msg = st.get("message") or self._message or "scanning…"
            scan_log(
                f"still running · {msg}  ({elapsed})",
                level="INF",
                verbose=self.verbose,
                anim=False,
            )

    def stop(self, final_msg: str = "", *, silent: bool = False, level: str = "OK") -> None:
        global _ACTIVE_HUD
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self._thread = None

        if silent:
            self.park()
            with _HUD_LOCK:
                if _ACTIVE_HUD is self:
                    _ACTIVE_HUD = None
            return

        if final_msg:
            update_pipeline_state(message=final_msg)
        st = _snap()
        if level == "OK" and int(st["host_total"]) > 0:
            update_pipeline_state(host_current=int(st["host_total"]))

        elapsed = _fmt_elapsed(time.time() - self._t0)
        msg = final_msg or self._message or "done"
        # Erase spinner without leaving a ghost "running" row
        if self._bar_open:
            _clear_cr_line()
            self._bar_open = False

        if self._mode != "off" and self.verbose >= 0:
            st = _snap()
            htot = int(st["host_total"])
            mtot = int(st["module_total"])
            if htot > 0:
                cur, tot = int(st["host_current"]), htot
            elif mtot > 0:
                cur, tot = int(st["module_current"]), mtot
            else:
                cur, tot = 1, 1
            if level == "OK":
                cur = tot
            p = _pct(cur, tot) if tot else 100.0
            if level == "OK":
                p = 100.0
            bar = cyber_bar(p, width=18, color="green" if level == "OK" else "red")
            icon = "✓" if level == "OK" else "✗"
            if _color_on():
                ic = _GREEN if level == "OK" else _RED
                line = (
                    f"  {_BOLD}{ic}{icon}{_R}  {bar}  {_BOLD}{p:3.0f}%{_R}  "
                    f"{msg}  {_GRAY}{elapsed}{_R}"
                )
            else:
                line = f"  {icon}  {bar}  {p:3.0f}%  {msg}  {elapsed}"
            with _IO:
                print(line)
                sys.stdout.flush()

        with _HUD_LOCK:
            if _ACTIVE_HUD is self:
                _ACTIVE_HUD = None
        self._bar_open = False


# ---------------------------------------------------------------------------
# Public API: scan_activity / HostProgress / PipelineProgress
# ---------------------------------------------------------------------------

class ScanActivity:
    def __init__(
        self,
        message: str,
        *,
        verbose: int = 1,
        style: str = "thinking",
        verb: str | None = None,
        host_total: int = 0,
        host_label: str = "Hosts",
        module_label: str | None = None,
        module_current: int | None = None,
        module_total: int | None = None,
        interval: float = 0.1,
    ):
        self.message = message
        self.verbose = verbose
        self.verb = verb
        update_pipeline_state(
            message=message,
            verb=verb,
            host_total=host_total if host_total else None,
            host_current=0 if host_total else None,
            host_label=host_label if host_total else None,
            module_label=module_label,
            module_current=module_current,
            module_total=module_total,
        )
        self._hud = LiveHUD(message, verbose=verbose, interval=interval)

    def set_hosts(self, current: int, total: int | None = None, item: str = "") -> None:
        update_pipeline_state(
            host_current=current,
            host_total=total,
            last_item=item or None,
        )

    def advance_host(self, item: str = "") -> None:
        st = _snap()
        update_pipeline_state(
            host_current=int(st["host_current"]) + 1,
            last_item=item or None,
        )

    def start(self) -> "ScanActivity":
        self._hud.start()
        return self

    def stop(self, final_msg: str = "", level: str = "OK") -> None:
        self._hud.stop(final_msg=final_msg or self.message, level=level)

    def __enter__(self) -> "ScanActivity":
        return self.start()

    def __exit__(self, *exc) -> None:
        if exc[0] is not None:
            self.stop(final_msg=f"{self.message} — failed", level="ERR")
        else:
            self.stop(final_msg=self.message, level="OK")


@contextmanager
def scan_activity(
    message: str,
    *,
    verbose: int = 1,
    style: str = "thinking",
    verb: str | None = None,
    host_total: int = 0,
    host_label: str = "Hosts",
    module_label: str | None = None,
    module_current: int | None = None,
    module_total: int | None = None,
) -> Iterator[ScanActivity]:
    act = ScanActivity(
        message,
        verbose=verbose,
        style=style,
        verb=verb,
        host_total=host_total,
        host_label=host_label,
        module_label=module_label,
        module_current=module_current,
        module_total=module_total,
    )
    act.start()
    try:
        yield act
    except Exception:
        act.stop(final_msg=f"{message} — failed", level="ERR")
        raise
    else:
        act.stop(final_msg=message, level="OK")


@dataclass
class HostProgress:
    """
    Per-host loop progress — same UX as ToolChecklist:
      ⠋  42/150  JS fetch/secrets  scanning…  host…  00:01:04   (\\r only)
      ✓  150/150  JS fetch/secrets  |████████| 100%  00:02:00   (one result)
    """

    label: str
    total: int
    phase: str = "default"
    verbose: int = 1
    current: int = 0
    last_item: str = ""
    _closed: bool = False
    _bar_open: bool = False
    _frame: int = 0
    _t0: float = field(default_factory=time.time)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = field(default=None, init=False)
    _anim_lock: threading.Lock = field(default_factory=threading.Lock)
    _owns_hud: bool = False

    def __post_init__(self) -> None:
        if self.total < 0:
            self.total = 0
        update_pipeline_state(
            host_label=self.label,
            host_total=self.total,
            host_current=0,
            last_item="",
            message=self.label,
        )
        if self.verbose < 0 or self.total <= 0:
            return
        if hud_active():
            # Nested under another HUD — only update counters, no second spinner
            return
        global _ACTIVE_HUD
        _ensure_vt()
        _stop_active_hud(silent=True)
        with _HUD_LOCK:
            _ACTIVE_HUD = self
        self._owns_hud = True
        self._t0 = time.time()
        self._stop.clear()
        ts = _ts()
        head = f"{_GRAY}[{ts}]{_R}  {_BOLD}{_CYAN}▸{_R}  {_BOLD}{self.label}{_R}  {_GRAY}({self.total} items){_R}" if _color_on() else f"[{ts}]  ▸  {self.label}  ({self.total} items)"
        with _IO:
            print(head)
            sys.stdout.flush()
        if can_animate():
            self._thread = threading.Thread(target=self._loop, name="host-progress", daemon=True)
            self._thread.start()
            self._paint()

    def is_alive(self) -> bool:
        return self._owns_hud and not self._closed

    def park(self) -> None:
        with self._anim_lock:
            if self._bar_open:
                _clear_cr_line()
                _end_bar_line()
                self._bar_open = False

    def update(self, n: int | None = None, item: str = "") -> None:
        if self._closed:
            return
        if n is None:
            self.current += 1
        else:
            self.current = n
        if item:
            self.last_item = item
        update_pipeline_state(
            host_current=self.current,
            host_total=self.total,
            host_label=self.label,
            last_item=item or None,
        )
        try:
            from run_control import CONTROL
            CONTROL.check()
        except Exception as e:
            if e.__class__.__name__ == "RunStopped":
                raise

    def advance(self, item: str = "") -> None:
        self.update(None, item)

    def _running_text(self) -> str:
        elapsed = _fmt_elapsed(time.time() - self._t0)
        spin = anim_block(self._frame)
        cur = min(self.current, self.total) if self.total else self.current
        tot = self.total or max(1, cur)
        item = self.last_item
        item_s = (item[:28] + "…") if len(item) > 28 else item
        try:
            from run_control import CONTROL
            paused = CONTROL.is_paused()
        except Exception:
            paused = False
        tag = "paused" if paused else "scanning"
        dots = think_dots(self._frame // 2)
        if _color_on():
            return (
                f"  {spin}  {_GRAY}{cur}/{tot}{_R}  "
                f"{_BOLD}{_WHITE}{self.label}{_R}  "
                f"{_YELLOW}{tag}{dots}{_R}  {_CYAN}{item_s}{_R}  {_GRAY}{elapsed}{_R}"
            )
        return f"  {spin}  {cur}/{tot}  {self.label}  {tag}{dots}  {item_s}  {elapsed}"

    def _paint(self) -> None:
        if not self._owns_hud or self._closed or not can_animate():
            return
        with self._anim_lock:
            if self._closed:
                return
            text = self._running_text()
            cols = min(100, _term_cols())
            fitted = _truncate_plain(text, max(40, cols - 2))
            pad = max(0, max(40, cols - 2) - len(_plain(fitted)))
            with _IO:
                sys.stdout.write("\r\033[2K" + fitted + (" " * pad))
                sys.stdout.flush()
            self._bar_open = True

    def _loop(self) -> None:
        while not self._stop.is_set() and not self._closed:
            self._frame += 1
            self._paint()
            self._stop.wait(0.12)

    def close(self, summary: str = "") -> None:
        global _ACTIVE_HUD
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self._thread = None
        self.current = max(self.current, self.total) if self.total else self.current
        update_pipeline_state(host_current=self.current, host_total=self.total)
        elapsed = _fmt_elapsed(time.time() - self._t0)
        tot = self.total or max(1, self.current)
        p = _pct(self.current, tot)
        bar = cyber_bar(p, width=18, color="green")
        extra = f"  · {summary}" if summary else ""
        with self._anim_lock:
            if self._bar_open:
                _clear_cr_line()
                self._bar_open = False
            with _IO:
                if _color_on():
                    print(
                        f"  {_BOLD}{_GREEN}✓{_R}  {_GRAY}{self.current}/{tot}{_R}  "
                        f"{_BOLD}{_WHITE}{self.label}{_R}  {bar}  {_BOLD}{p:3.0f}%{_R}  "
                        f"{_GRAY}{elapsed}{_R}{_GRAY}{extra}{_R}"
                    )
                else:
                    print(
                        f"  ✓  {self.current}/{tot}  {self.label}  {bar}  "
                        f"{p:3.0f}%  {elapsed}{extra}"
                    )
                sys.stdout.flush()
        if self._owns_hud:
            with _HUD_LOCK:
                if _ACTIVE_HUD is self:
                    _ACTIVE_HUD = None
            self._owns_hud = False

    def stop(self, silent: bool = False, **_kwargs) -> None:
        """Compatibility with _stop_active_hud."""
        if silent:
            self._closed = True
            self._stop.set()
            with self._anim_lock:
                if self._bar_open:
                    _clear_cr_line()
                    self._bar_open = False
            global _ACTIVE_HUD
            with _HUD_LOCK:
                if _ACTIVE_HUD is self:
                    _ACTIVE_HUD = None
            return
        self.close()


def _box_inner_pad(text: str, inner_width: int) -> str:
    """
    Pad plain text to exactly inner_width display columns.

    Avoid emoji/VS16 in box titles — many Linux fonts render 🛰️ as a lone
    variation-selector glyph, and .ljust() ignores double-width cells so the
    right border drifts.
    """
    # Strip any accidental ANSI before measuring
    plain = _plain(text)
    if len(plain) > inner_width:
        if inner_width <= 3:
            return plain[:inner_width]
        return plain[: inner_width - 1] + "…"
    return plain + (" " * (inner_width - len(plain)))


def _print_ops_banner(target: str, modules: list[str]) -> None:
    """Pipeline start box — aligned borders, module route."""
    width = 72
    inner = width - 2
    total = len(modules)
    tgt = target or "target"
    phases_s = f"{total} SHIP{'S' if total != 1 else ''}"
    prefix = "  ▶  RECON  ·  "
    mid = "  ·  "
    room = inner - len(prefix) - len(mid) - len(phases_s)
    if room < 8:
        room = 8
    tgt_disp = tgt if len(tgt) <= room else (tgt[: room - 1] + "…")
    title = _box_inner_pad(f"{prefix}{tgt_disp}{mid}{phases_s}", inner)

    # Short fleet names on route (colored per ship)
    fleet_bits_plain = []
    fleet_bits_color = []
    for m in modules:
        ship, _klass = FLEET_SHIPS.get(m, (m, ""))
        short = ship.replace("USS ", "") if ship.startswith("USS ") else m
        fleet_bits_plain.append(short)
        ac = fleet_ship_color(m) if _color_on() else ""
        fleet_bits_color.append(f"{ac}{short}{_R}" if _color_on() else short)

    if _color_on():
        print()
        print(_c(_BOLD, _YELLOW) + "╔" + "═" * inner + "╗" + _R)
        print(
            _c(_BOLD, _YELLOW) + "║" + _R
            + _c(_BOLD, _WHITE) + title + _R
            + _c(_BOLD, _YELLOW) + "║" + _R
        )
        print(_c(_BOLD, _YELLOW) + "╚" + "═" * inner + "╝" + _R)
        arrow = f"{_GRAY} → {_R}"
        print(f"{_GRAY}  modules: {_R}" + arrow.join(fleet_bits_color))
        print(_c(_GRAY) + "  orders: /pause  /resume  /stop  ·  /jobs  ·  /dashboard" + _R)
        print()
    else:
        print()
        print("+" + "-" * inner + "+")
        print("|" + title + "|")
        print("+" + "-" * inner + "+")
        print("  modules: " + " → ".join(fleet_bits_plain))
        print("  orders: /pause  /resume  /stop  ·  /jobs")
        print()


@dataclass
class PipelineProgress:
    modules: list[str]
    verbose: int = 1
    target: str = ""
    _idx: int = 0
    _t0: float = field(default_factory=time.time)

    def start(self) -> None:
        total = len(self.modules)
        tgt = self.target or "target"
        update_pipeline_state(
            module_label="Modules",
            module_current=0,
            module_total=total,
            host_label="Hosts",
            host_current=0,
            host_total=0,
        )
        try:
            from run_control import CONTROL
            CONTROL.reset(label=f"pipeline:{tgt}")
        except Exception:
            pass
        try:
            from live_mission import start_run
            start_run(
                target=tgt,
                modules=list(self.modules),
                outdir="",
                source="pipeline",  # may be overridden by caller start_run
            )
        except Exception:
            pass
        if self.verbose <= 0:
            scan_log(
                f"PIPELINE · {tgt} · {total} phase(s)",
                level="INF",
                verbose=self.verbose,
            )
            return
        _print_ops_banner(tgt, list(self.modules))
        if self.verbose >= 2:
            scan_log(f"Starting enumeration for {tgt}", level="INF", frame=1, verbose=self.verbose)

    def begin_module(self, name: str) -> None:
        try:
            from run_control import CONTROL
            CONTROL.check()
        except Exception as e:
            if e.__class__.__name__ == "RunStopped":
                raise
        self._idx += 1
        total = max(1, len(self.modules))
        update_pipeline_state(
            module_label=f"Modules ({name})",
            module_current=self._idx - 1,
            module_total=total,
            host_current=0,
            host_total=0,
            last_item="",
        )
        try:
            from live_mission import begin_phase
            begin_phase(name, self._idx, total)
        except Exception:
            pass
        _stop_active_hud(silent=True)
        # Per-module colorized ship banner (unique hull per phase)
        if self.verbose >= 1:
            print_module_ship_banner(
                name,
                index=self._idx,
                total=total,
                detail=f"module={name}",
                animate=can_animate(),
            )
        if self.verbose >= 2:
            scan_log(
                f"{phase_emoji(name)} PHASE {self._idx}/{total} · {phase_title(name)} [{name}]",
                level="RUN",
                frame=self._idx * 3,
                verbose=self.verbose,
            )

    def end_module(self, name: str, elapsed: float | None = None) -> None:
        total = max(1, len(self.modules))
        update_pipeline_state(
            module_label=f"Modules ({name})",
            module_current=self._idx,
            module_total=total,
        )
        try:
            from live_mission import end_phase
            end_phase(name, elapsed=elapsed)
        except Exception:
            pass
        _stop_active_hud(silent=True)
        # One compact phase-complete line (no second INF log at normal verbosity)
        p = _pct(self._idx, total)
        bar = cyber_bar(p, width=20, color="green")
        ship, _ = FLEET_SHIPS.get(name, (name, ""))
        t = f"  {elapsed:.1f}s" if elapsed is not None else ""
        with _IO:
            if _color_on():
                print(
                    f"  {_GREEN}✔{_R}  {bar}  {_BOLD}{self._idx}/{total}{_R}  "
                    f"{_WHITE}{ship}{_R}{_GRAY}{t}{_R}"
                )
            else:
                print(f"  ✔  {bar}  {self._idx}/{total}  {ship}{t}")
            sys.stdout.flush()
        if self.verbose >= 2:
            scan_log(
                f"{phase_emoji('done')} phase complete · {name}{t}  ({self._idx}/{total})",
                level="OK",
                frame=self._idx * 3,
                verbose=self.verbose,
                anim=False,
            )

    def set_host_total(self, n: int) -> None:
        update_pipeline_state(host_total=n, host_current=0)
        try:
            from live_mission import set_hosts
            set_hosts(total=n, current=0)
        except Exception:
            pass

    def finish(self, outdir: str = "") -> None:
        elapsed = time.time() - self._t0
        update_pipeline_state(
            module_current=len(self.modules),
            module_total=len(self.modules),
            module_label="Modules",
        )
        try:
            from live_mission import finish_run
            finish_run(ok=True, outdir=outdir)
        except Exception:
            pass
        _stop_active_hud(silent=True)
        st = _snap()
        mp = _pct(int(st["module_current"]), int(st["module_total"]))
        bar = cyber_bar(mp, 24, "green")
        with _IO:
            if _color_on():
                print(
                    f"  {_BOLD}{_GREEN}✔{_R}  {bar}  {_BOLD}SCAN COMPLETE{_R}  "
                    f"{len(self.modules)} modules  {_GRAY}{_fmt_elapsed(elapsed)}{_R}"
                    + (f"  {_DIM}{_GRAY}→ {outdir}{_R}" if outdir else "")
                )
            else:
                print(
                    f"  ✔  {bar}  SCAN COMPLETE  {len(self.modules)} modules  "
                    f"{_fmt_elapsed(elapsed)}"
                    + (f"  → {outdir}" if outdir else "")
                )
            print()
            sys.stdout.flush()


def phase_banner(name: str, detail: str = "", verbose: int = 1) -> None:
    scan_log(
        f"{phase_emoji(name)} {phase_title(name)}"
        + (f" // {detail}" if detail else ""),
        level="INF",
        frame=hash(name) % 20,
        verbose=verbose,
    )


def tool_progress(label: str, current: int, total: int, verbose: int = 1) -> None:
    if verbose < 1:
        return
    update_pipeline_state(
        module_label=f"Modules ({label})",
        module_current=current,
        module_total=total,
    )
    if not hud_active():
        p = _pct(current, total)
        bar = cyber_bar(p, width=22, color="blue")
        with _IO:
            print(f"  🛠 {label}  {bar}  {current}/{total}  {p:5.1f}%")
            sys.stdout.flush()


def hosts_progress(
    label: str,
    total: int,
    *,
    phase: str = "default",
    verbose: int = 1,
) -> HostProgress:
    return HostProgress(label=label, total=total, phase=phase, verbose=verbose)


def iter_hosts(
    items: list,
    *,
    label: str,
    phase: str = "default",
    verbose: int = 1,
    item_str: Callable | None = None,
):
    from run_control import CONTROL, RunStopped

    hp = hosts_progress(label, len(items), phase=phase, verbose=verbose)
    try:
        for it in items:
            CONTROL.check()
            s = item_str(it) if item_str else str(it)
            hp.advance(s)
            yield it
    except RunStopped:
        hp.close("stopped")
        raise
    finally:
        if not hp._closed:
            hp.close()


# Enable VT early when this module is imported on Windows
_ensure_vt()
