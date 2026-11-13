"""Plain scan status lines.

A scan prints one phase line, one row when a tool finishes, and one
completion line. HTTP probe prints one line per host. There is no
spinner and no progress bar.
"""

from __future__ import annotations

import os
import sys
import threading
import time

_GREEN = "\033[92m"
_CYAN = "\033[96m"
_YELLOW = "\033[93m"
_RED = "\033[91m"

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

_PHASE_KIND = {
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

_IO = threading.RLock()
_HUD_LOCK = threading.Lock()
_ACTIVE_HUD = None
_CHECKLIST_TLS = threading.local()


def _color_on() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _mark(tag: str, color: str) -> str:
    if _color_on():
        return f"\033[1m{color}{tag}\033[0m"
    return tag


def _emit(line: str) -> None:
    with _IO:
        print(line)
        sys.stdout.flush()


def _fmt_elapsed(seconds: float) -> str:
    s = int(max(0, seconds))
    m, s = divmod(s, 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _phase_label(name: str) -> tuple[str, str]:
    key = (name or "default").lower().strip()
    return _PHASE_KIND.get(key, _PHASE_KIND["default"])


def phase_title(name: str) -> str:
    key = (name or "default").lower().strip()
    return PHASE_TITLE.get(key, key.replace("_", " ").upper())


def prepare_foreground_progress() -> None:
    """Foreground scans print the same plain lines as any other run."""
    return


def hud_active() -> bool:
    """True while a checklist or host loop owns the scan status."""
    with _HUD_LOCK:
        hud = _ACTIVE_HUD
    if hud is None or getattr(hud, "_closed", False):
        return False
    return True


def _set_hud(hud) -> None:
    global _ACTIVE_HUD
    with _HUD_LOCK:
        _ACTIVE_HUD = hud


def _clear_hud(hud) -> None:
    global _ACTIVE_HUD
    with _HUD_LOCK:
        if _ACTIVE_HUD is hud:
            _ACTIVE_HUD = None


def _stop_active() -> None:
    global _ACTIVE_HUD
    with _HUD_LOCK:
        hud = _ACTIVE_HUD
        _ACTIVE_HUD = None
    if hud is None:
        return
    try:
        hud.stop(silent=True)
    except Exception:
        pass


def _check_stopped() -> None:
    try:
        from run_control import CONTROL
        CONTROL.check()
    except Exception as exc:
        if exc.__class__.__name__ == "RunStopped":
            raise


def hud_print(text: str) -> None:
    _emit(text)


def scan_log(
    msg: str,
    *,
    level: str = "INF",
    frame: int = 0,
    verbose: int = 1,
    min_level: int = 0,
    anim: bool = True,
) -> None:
    del frame, anim
    if verbose < min_level:
        return
    tag, color = {
        "OK": ("[+]", _GREEN),
        "WRN": ("[!]", _YELLOW),
        "ERR": ("[-]", _RED),
    }.get(level.upper()[:3], ("[*]", _CYAN))
    hud_print(f"{_mark(tag, color)} {msg}")


def suppress_checklist(on: bool) -> None:
    """This thread skips the shared tool list.

    Overlapping phases each used to install a checklist and replace the
    other one's status. The work still runs. The phase line stays.
    """
    _CHECKLIST_TLS.quiet = bool(on)


def phase_banner(name: str, detail: str = "", verbose: int = 1) -> None:
    extra = f" {detail}" if detail else ""
    scan_log(f"{phase_title(name)}{extra}", level="INF", verbose=verbose)


class _ToolRow:
    def __init__(self, name: str, index: int) -> None:
        self.name = name
        self.status = "pending"
        self.value = ""
        self.detail = ""
        self.index = index


class ToolChecklist:
    """One row per finished tool, then one summary row."""

    def __init__(
        self,
        tools: list[str],
        *,
        title: str = "Tools",
        verbose: int = 1,
        interval: float = 0.12,
    ):
        del interval
        self.verbose = verbose
        self.title = title
        self.rows = [_ToolRow(name=t, index=i) for i, t in enumerate(tools, 1)]
        self._by_name = {row.name: row for row in self.rows}
        self._t0 = time.time()
        self._closed = False
        self._started = False
        self._lock = threading.Lock()
        self._name_w = max(12, min(14, max((len(t) for t in tools), default=12)))

    def start(self) -> "ToolChecklist":
        if self.verbose < 0 or self._closed:
            return self
        _stop_active()
        _set_hud(self)
        self._started = True
        self._t0 = time.time()
        return self

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
        if status is not None:
            row.status = status
        if value is not None:
            row.value = str(value)
        if detail:
            row.detail = detail

    def start_tool(self, name: str) -> None:
        _check_stopped()
        if self.verbose < 0 or self._closed:
            return
        with self._lock:
            self.set(name, status="running", value="")

    def finish_tool(
        self,
        name: str,
        count: int | str | None = None,
        *,
        ok: bool = True,
        skipped: bool = False,
        detail: str = "",
    ) -> None:
        if self.verbose < 0 or self._closed:
            return
        with self._lock:
            if skipped:
                self.set(name, status="skip", value="skip", detail=detail)
            elif not ok:
                self.set(name, status="fail", value="fail", detail=detail)
            else:
                val = "0" if count is None else str(count)
                self.set(name, status="done", value=val, detail=detail)
            done = sum(1 for row in self.rows if row.status in ("done", "skip", "fail"))
            self._print_result(name, done)

    def _print_result(self, name: str, shown_index: int) -> None:
        row = self._by_name.get(name)
        if row is None:
            return
        total = max(1, len(self.rows))
        elapsed = _fmt_elapsed(time.time() - self._t0)
        width = len(f"{total}/{total}")
        idx = f"{shown_index}/{total}".rjust(width)
        tag, color = {
            "done": ("[+]", _GREEN),
            "skip": ("[*]", _CYAN),
            "fail": ("[-]", _RED),
        }.get(row.status, ("[*]", _CYAN))
        extra = f"  {row.detail}" if row.detail else ""
        _emit(
            f"{_mark(tag, color)}  {idx}  {name:<{self._name_w}}  "
            f"{row.value:>7}  {elapsed}{extra}"
        )

    def stop(self, final_msg: str = "", *, silent: bool = False, level: str = "OK") -> None:
        del level
        if self._closed:
            return
        self._closed = True
        _clear_hud(self)
        if silent or self.verbose < 0:
            return
        if final_msg:
            self.title = final_msg
        done_n = sum(1 for row in self.rows if row.status == "done")
        skipped = sum(1 for row in self.rows if row.status == "skip")
        failed = sum(1 for row in self.rows if row.status == "fail")
        total = len(self.rows)
        elapsed = _fmt_elapsed(time.time() - self._t0)
        summary = f"{done_n} ok"
        if skipped:
            summary += f" · {skipped} skip"
        if failed:
            summary += f" · {failed} fail"
        finished = done_n + skipped + failed
        _emit(f"{_mark('[+]', _GREEN)}  {finished}/{total} tools  {summary}  {elapsed}")
        if self.verbose >= 2:
            scan_log(
                f"{self.title}  ·  {summary}  ({elapsed})",
                level="OK",
                verbose=self.verbose,
            )

    def __enter__(self) -> "ToolChecklist":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop(level="ERR" if exc[0] is not None else "OK")


def tool_checklist(
    tools: list[str],
    *,
    title: str = "Tools",
    verbose: int = 1,
) -> ToolChecklist:
    if getattr(_CHECKLIST_TLS, "quiet", False):
        verbose = -1
    checklist = ToolChecklist(tools, title=title, verbose=verbose)
    checklist.start()
    return checklist


class ProbeProgress:
    """One line per host that answers, and one line per host that does not."""

    def __init__(self, total: int, *, interval: float = 0.12, verbose: int = 1):
        del interval
        self.total = max(0, int(total))
        self.verbose = verbose
        self._hits = 0
        self._closed = False
        self._lock = threading.Lock()

    def start(self) -> "ProbeProgress":
        if self.verbose < 1 or self._closed:
            return self
        _stop_active()
        _set_hud(self)
        return self

    def hit(self, name: str, detail: str = "") -> None:
        self._row("[+]", _GREEN, name, detail, advance=True)

    def miss(self, name: str, detail: str = "no response") -> None:
        self._row("[-]", _RED, name, detail, advance=False)

    def _row(self, tag: str, color: str, name: str, detail: str, *, advance: bool) -> None:
        if self.verbose < 1 or self._closed:
            return
        name = (name or "").strip()
        if not name:
            return
        with self._lock:
            idx = ""
            if advance:
                self._hits += 1
                if self.total > 0:
                    width = len(f"{self.total}/{self.total}")
                    idx = f"{self._hits}/{self.total}".rjust(width)
            extra = f"  {detail}" if detail else ""
            gap = f"  {idx}  " if idx else "  "
            _emit(f"{_mark(tag, color)}{gap}{name}{extra}")

    def stop(self, final_msg: str = "", *, silent: bool = False, **_kwargs) -> None:
        del final_msg, silent
        if self._closed:
            return
        self._closed = True
        _clear_hud(self)


class HostProgress:
    """One start line and one finished count for a host loop."""

    def __init__(
        self,
        label: str,
        total: int = 0,
        *,
        phase: str = "default",
        verbose: int = 1,
    ):
        del phase
        self.label = label
        self.total = max(0, int(total))
        self.verbose = verbose
        self.current = 0
        self._closed = False
        self._owns = False
        self._t0 = time.time()
        if self.verbose < 1 or self.total <= 0:
            return
        if hud_active():
            return
        _stop_active()
        _set_hud(self)
        self._owns = True
        self._t0 = time.time()
        _emit(f"{_mark('[*]', _CYAN)} {self.label}  {self.total}")

    def advance(self, item: str = "") -> None:
        del item
        if self._closed:
            return
        self.current += 1
        _check_stopped()

    def close(self, summary: str = "") -> None:
        if self._closed:
            return
        self._closed = True
        _clear_hud(self)
        self._owns = False
        if self.verbose < 1 or self.total <= 0:
            return
        elapsed = _fmt_elapsed(time.time() - self._t0)
        extra = f"  {summary}" if summary else ""
        shown = min(self.current, self.total) if self.current else self.total
        _emit(
            f"{_mark('[+]', _GREEN)}  {shown}/{self.total}  {self.label}  {elapsed}{extra}"
        )

    def stop(self, final_msg: str = "", *, silent: bool = False, **_kwargs) -> None:
        if self._closed:
            return
        if silent:
            self._closed = True
            _clear_hud(self)
            self._owns = False
            return
        self.close(final_msg)


class PipelineProgress:
    def __init__(self, modules: list[str], verbose: int = 1, target: str = ""):
        self.modules = list(modules)
        self.verbose = verbose
        self.target = target
        self._idx = 0
        self._t0 = time.time()

    def start(self) -> None:
        total = len(self.modules)
        target = self.target or "target"
        try:
            from run_control import CONTROL
            CONTROL.reset(label=f"pipeline:{target}")
        except Exception:
            pass
        self._t0 = time.time()
        if self.verbose <= 0:
            scan_log(f"PIPELINE · {target} · {total} phase(s)", verbose=self.verbose)
            return
        names = ", ".join(self.modules)
        _emit(f"{_mark('[*]', _CYAN)} {target}  {total} modules: {names}")
        _emit(f"{_mark('[*]', _CYAN)} Ctrl+C stops this scan")
        if self.verbose >= 2:
            scan_log(f"Starting enumeration for {target}", verbose=self.verbose)

    def begin_module(self, name: str) -> None:
        _check_stopped()
        self._idx += 1
        _stop_active()
        if self.verbose < 1:
            return
        total = max(1, len(self.modules))
        title, kind = _phase_label(name)
        _emit(f"{_mark('[*]', _CYAN)} {self._idx}/{total} {title}  {kind}")
        if self.verbose >= 2:
            scan_log(
                f"PHASE {self._idx}/{total} · {phase_title(name)} [{name}]",
                verbose=self.verbose,
            )

    def end_module(self, name: str, elapsed: float | None = None) -> None:
        _stop_active()
        if self.verbose < 2:
            return
        total = max(1, len(self.modules))
        spent = f"  {elapsed:.1f}s" if elapsed is not None else ""
        scan_log(
            f"phase complete · {name}{spent}  ({self._idx}/{total})",
            level="OK",
            verbose=self.verbose,
        )

    def set_host_total(self, n: int) -> None:
        del n

    def finish(self, outdir: str = "") -> None:
        elapsed = _fmt_elapsed(time.time() - self._t0)
        _stop_active()
        tail = f"  {outdir}" if outdir else ""
        _emit(
            f"{_mark('[+]', _GREEN)} SCAN COMPLETE  "
            f"{len(self.modules)} modules  {elapsed}{tail}"
        )
