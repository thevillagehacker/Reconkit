"""Tool-row layout. Run: python tests/test_progress_ui.py"""

from __future__ import annotations

import io
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

os.environ["NO_COLOR"] = "1"
_HOME = tempfile.mkdtemp(prefix="reconkit-progress-")
os.environ["RECONKIT_HOME"] = _HOME

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import progress_ui as ui  # noqa: E402


def _capture(fn) -> str:
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        fn()
    finally:
        sys.stdout = old
    return buf.getvalue()


def _visible(text: str) -> list[str]:
    """Lines as a terminal shows them: last segment after \\r, ANSI stripped."""
    shown: list[str] = []
    for raw in text.splitlines():
        line = raw.split("\r")[-1]
        line = re.sub(r"\033\[[0-9;]*[A-Za-z]", "", line)
        if line.strip():
            shown.append(line)
    return shown


def test_finished_rows_count_up_and_the_spinner_does_not() -> None:
    cl = ui.ToolChecklist(
        ["amass", "findomain", "hackertarget"],
        title="Subdomain enum",
        verbose=1,
    )
    cl.set("amass", status="running")
    cl._current_running = "amass"
    running = cl._running_text()
    assert "amass" in running
    assert "running" in running
    assert "running." not in running
    assert "0/3" in running
    assert "1/3" not in running
    assert "|" in running

    def finish_out_of_order() -> None:
        cl.finish_tool("findomain", skipped=True, detail="not found")
        cl.finish_tool("amass", 0)

    text = _capture(finish_out_of_order)
    findomain, amass = [ln for ln in _visible(text) if "running" not in ln]
    assert "1/3" in findomain and "findomain" in findomain
    assert "2/3" not in findomain
    assert "not found" in findomain
    assert "█" not in findomain and "%" not in findomain
    assert "2/3" in amass and "amass" in amass
    assert "1/3" not in amass
    assert "0" in amass
    assert "█" not in amass and "%" not in amass


def test_summary_is_one_line() -> None:
    cl = ui.ToolChecklist(["amass", "findomain"], title="Subdomain enum", verbose=1)
    cl.set("amass", status="done", value="3")
    cl.set("findomain", status="skip", value="skip")

    text = _capture(lambda: cl.stop())
    assert "2/2 tools" in text
    assert "1 ok" in text
    assert "1 skip" in text
    assert "█" not in text
    assert "[OK]" not in text
    assert "▸" not in text


def test_warning_takes_its_own_line() -> None:
    class Fake:
        def __init__(self) -> None:
            self._bar_open = True
            self._closed = False
            self._anim_lock = threading.Lock()

    fake = Fake()
    old_hud = ui._ACTIVE_HUD
    old_anim = ui.can_animate
    ui._ACTIVE_HUD = fake
    ui.can_animate = lambda: True
    try:
        text = _capture(lambda: ui.hud_print("[WARN] amass: hard cap 180s"))
    finally:
        ui._ACTIVE_HUD = old_hud
        ui.can_animate = old_anim
    assert text.startswith("\r\033[K")
    assert "\033[2K" not in text
    assert text.endswith("[WARN] amass: hard cap 180s\n")
    assert fake._bar_open is False
    assert "running" not in text


def test_background_tty_prints_finish_rows_only() -> None:
    old_bg = os.environ.get("RECONKIT_BG")
    old_forced = os.environ.get("RECONKIT_PROGRESS")
    old_isatty = sys.stdout.isatty
    os.environ["RECONKIT_BG"] = "1"
    os.environ.pop("RECONKIT_PROGRESS", None)
    sys.stdout.isatty = lambda: True  # type: ignore[method-assign]
    try:
        assert ui.progress_mode() == "log"
        assert ui.can_animate() is False
        cl = ui.ToolChecklist(["amass", "otx"], title="Subdomain enum", verbose=1)
        cl.start()
        assert cl._thread is None
        started = _capture(lambda: cl.start_tool("amass"))
        assert started.strip() == ""
        finished = _capture(lambda: cl.finish_tool("amass", 4))
        assert "\r" not in finished
        assert "1/2" in finished and "amass" in finished
        assert "running" not in finished
        assert "|" not in finished
        cl.stop(silent=True)
    finally:
        sys.stdout.isatty = old_isatty  # type: ignore[method-assign]
        if old_bg is None:
            os.environ.pop("RECONKIT_BG", None)
        else:
            os.environ["RECONKIT_BG"] = old_bg
        if old_forced is None:
            os.environ.pop("RECONKIT_PROGRESS", None)
        else:
            os.environ["RECONKIT_PROGRESS"] = old_forced


def test_spinner_stays_while_another_tool_runs() -> None:
    """A fast finish must not erase the spinner before the slow tool ends.

    isatty() is false here, which is the case that left findomain running
    for many seconds with only finish rows on screen.
    """
    old_bg = os.environ.get("RECONKIT_BG")
    old_forced = os.environ.get("RECONKIT_PROGRESS")
    os.environ.pop("RECONKIT_BG", None)
    os.environ.pop("RECONKIT_PROGRESS", None)

    class _Cap:
        def __init__(self) -> None:
            self.parts: list[str] = []

        def write(self, text: str) -> int:
            self.parts.append(text)
            return len(text)

        def flush(self) -> None:
            return None

        def isatty(self) -> bool:
            return False

    cap = _Cap()
    old_out = sys.stdout
    sys.stdout = cap  # type: ignore[assignment]
    cl = None
    try:
        assert ui.progress_mode() == "live"
        assert ui.can_animate() is True
        cl = ui.ToolChecklist(
            ["chaos", "findomain"],
            title="Subdomain enum",
            verbose=1,
            interval=0.05,
        )
        cl.start()
        assert cl._thread is not None and cl._thread.is_alive()
        cl.start_tool("chaos")
        cl.start_tool("findomain")
        time.sleep(0.2)
        cl.finish_tool("chaos", 103)
        time.sleep(0.45)
        raw = "".join(cap.parts)
    finally:
        if cl is not None:
            cl.stop(silent=True)
        sys.stdout = old_out
        if old_bg is None:
            os.environ.pop("RECONKIT_BG", None)
        else:
            os.environ["RECONKIT_BG"] = old_bg
        if old_forced is None:
            os.environ.pop("RECONKIT_PROGRESS", None)
        else:
            os.environ["RECONKIT_PROGRESS"] = old_forced

    assert "[+] " in raw and "chaos" in raw
    assert "\033[2K" not in raw
    after = raw.split("chaos", 1)[1]
    frames = [part for part in after.split("\r") if "findomain" in part and "running" in part]
    assert len(frames) >= 2, after[-400:]
    assert any("|" in frame and ("█" in frame or "░" in frame or "▓" in frame) for frame in frames)
    assert any(ch in after for ch in "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
    for frame in frames:
        assert frame.endswith("\033[K")
        plain = re.sub(r"\033\[[0-9;]*[A-Za-z]", "", frame)
        assert len(plain) <= 78, plain


def test_spinner_glyph_is_colored_when_color_is_on() -> None:
    old_no = os.environ.pop("NO_COLOR", None)
    old_force = os.environ.get("FORCE_COLOR")
    os.environ["FORCE_COLOR"] = "1"
    try:
        glyphs = [ui.anim_block(i) for i in range(4)]
        assert [g for g in glyphs if "\033[" in g] == glyphs
        assert "⠋" in glyphs[0] and "⠙" in glyphs[1]
        assert len({g.split("m", 1)[0] for g in glyphs}) == 4
        assert re.sub(r"\033\[[0-9;]*[A-Za-z]", "", glyphs[0]) == "⠋"
    finally:
        os.environ["NO_COLOR"] = old_no if old_no is not None else "1"
        if old_force is None:
            os.environ.pop("FORCE_COLOR", None)
        else:
            os.environ["FORCE_COLOR"] = old_force
    assert ui.anim_block(0) == "⠋"


def test_phase_end_leaves_one_completion_bar() -> None:
    pipe = ui.PipelineProgress(["httpprobe"], verbose=1, target="globe.gov")
    pipe._idx = 1
    ended = _capture(lambda: pipe.end_module("httpprobe", 43.0))
    assert "█" not in ended
    assert "HTTP probe" not in ended
    done = _capture(lambda: pipe.finish("/tmp/globe.gov"))
    assert "SCAN COMPLETE" in done
    assert "█" in done


def test_probe_progress_records_each_host() -> None:
    probe = ui.ProbeProgress(2, interval=10, verbose=1)
    text = _capture(
        lambda: (
            probe.hit("https://www.globe.gov", "200"),
            probe.miss("old.globe.gov", "no response"),
        )
    )
    shown = [ln for ln in _visible(text) if "scanning" not in ln]
    hit = next(ln for ln in shown if "www.globe.gov" in ln)
    miss = next(ln for ln in shown if "old.globe.gov" in ln)
    assert hit.startswith("[+]") and "1/2" in hit and "200" in hit
    assert "█" not in hit
    assert miss.startswith("[-]") and "no response" in miss
    assert "1/2" not in miss


def test_http_probe_stream_splits_partial_lines() -> None:
    import reconkit as rk

    lines, rest = rk.split_stream_lines("", "https://a.example [200]\nhttps://b")
    assert lines == ["https://a.example [200]"]
    assert rest == "https://b"
    lines, rest = rk.split_stream_lines(rest, ".example [301]\n")
    assert lines == ["https://b.example [301]"]
    assert rest == ""
    feed = rk._HttpProbeFeed(None, ["a.example", "old.example"])
    feed.write(b"https://a.example [200] [Home]\nhttps://a.example/path")
    feed.flush_tail()
    assert feed.responded == {"a.example"}
    missed: list[str] = []

    class _Rec:
        def miss(self, name: str, detail: str = "") -> None:
            missed.append(f"{name} {detail}")

    feed.progress = _Rec()
    feed.misses()
    assert missed == ["old.example no response"]


def test_foreground_scan_drops_a_stale_background_flag() -> None:
    old_bg = os.environ.get("RECONKIT_BG")
    old_forced = os.environ.get("RECONKIT_PROGRESS")
    os.environ["RECONKIT_BG"] = "1"
    os.environ.pop("RECONKIT_PROGRESS", None)
    try:
        assert ui.progress_mode() == "log"
        ui.prepare_foreground_progress()
        assert "RECONKIT_BG" not in os.environ
        assert ui.progress_mode() == "live"
        assert ui.can_animate() is True
    finally:
        if old_bg is None:
            os.environ.pop("RECONKIT_BG", None)
        else:
            os.environ["RECONKIT_BG"] = old_bg
        if old_forced is None:
            os.environ.pop("RECONKIT_PROGRESS", None)
        else:
            os.environ["RECONKIT_PROGRESS"] = old_forced


def test_foreground_tty_still_animates() -> None:
    old_bg = os.environ.get("RECONKIT_BG")
    old_forced = os.environ.get("RECONKIT_PROGRESS")
    old_isatty = sys.stdout.isatty
    os.environ.pop("RECONKIT_BG", None)
    os.environ.pop("RECONKIT_PROGRESS", None)
    sys.stdout.isatty = lambda: True  # type: ignore[method-assign]
    try:
        assert ui.progress_mode() == "live"
        assert ui.can_animate() is True
    finally:
        sys.stdout.isatty = old_isatty  # type: ignore[method-assign]
        if old_bg is None:
            os.environ.pop("RECONKIT_BG", None)
        else:
            os.environ["RECONKIT_BG"] = old_bg
        if old_forced is None:
            os.environ.pop("RECONKIT_PROGRESS", None)
        else:
            os.environ["RECONKIT_PROGRESS"] = old_forced


def test_tool_timeout_clamps_and_rejects_junk() -> None:
    import reconkit as rk

    tmp = Path(_HOME) / "config.json"
    old_cfg = rk.CONFIG_FILE
    old_env = os.environ.get("RECON_AMASS_TIMEOUT")
    rk.CONFIG_FILE = tmp
    os.environ.pop("RECON_AMASS_TIMEOUT", None)
    try:
        name, val = rk.set_tool_timeout("RECON_AMASS_TIMEOUT", "900")
        assert (name, val) == ("RECON_AMASS_TIMEOUT", 900)
        assert os.environ["RECON_AMASS_TIMEOUT"] == "900"
        _name, clamped = rk.set_tool_timeout("recon_amass_timeout", "99999")
        assert clamped == 900
        try:
            rk.set_tool_timeout("RECON_AMASS_TIMEOUT", "nope")
            raise AssertionError("junk accepted")
        except ValueError:
            pass
        try:
            rk.set_tool_timeout("PATH", "1")
            raise AssertionError("unknown name accepted")
        except ValueError:
            pass
        os.environ["RECON_AMASS_TIMEOUT"] = "200"
        rk.apply_saved_timeouts()
        assert os.environ["RECON_AMASS_TIMEOUT"] == "200"
        os.environ.pop("RECON_AMASS_TIMEOUT", None)
        rk.apply_saved_timeouts()
        assert os.environ["RECON_AMASS_TIMEOUT"] == "900"
        parser = rk.build_parser()
        listed = parser.parse_args(["set"])
        assert listed.name == "" and listed.seconds is None
        chosen = parser.parse_args(["set", "RECON_AMASS_TIMEOUT", "900"])
        assert chosen.name == "RECON_AMASS_TIMEOUT" and chosen.seconds == "900"
    finally:
        rk.CONFIG_FILE = old_cfg
        if old_env is None:
            os.environ.pop("RECON_AMASS_TIMEOUT", None)
        else:
            os.environ["RECON_AMASS_TIMEOUT"] = old_env


def test_debug_lines_hide_the_chaos_key() -> None:
    import reconkit as rk

    secret = "test-chaos-key-value-123456"
    old = os.environ.get("PDCP_API_KEY")
    os.environ["PDCP_API_KEY"] = secret
    try:
        line = rk.redact_cmd([
            "/home/naveen/go/bin/chaos", "-key", secret,
            "-d", "example.com", "-silent",
        ])
        assert secret not in line
        assert "-key <redacted>" in line
        assert "example.com" in line
        inline = rk.redact_cmd(["/usr/bin/curl", f"--api-key={secret}", "https://example.com"])
        assert secret not in inline
        assert "--api-key=<redacted>" in inline
        header = rk.redact_cmd(["/usr/bin/curl", "-H", f"Authorization: Bearer {secret}"])
        assert secret not in header
        assert "Authorization: <redacted>" in header
        plain = rk.redact_cmd(["/usr/bin/curl", "-s", "https://crt.sh/?q=example.com"])
        assert "example.com" in plain
        assert "<redacted>" not in plain
        note = rk._scrub_secrets(f"auth failed for {secret}")
        assert secret not in note
        assert "<redacted>" in note
    finally:
        if old is None:
            os.environ.pop("PDCP_API_KEY", None)
        else:
            os.environ["PDCP_API_KEY"] = old


def test_otx_warns_only_on_a_refusal() -> None:
    import reconkit as rk

    hosts, reason = rk.otx_hosts_from_body("")
    assert hosts is None and reason == ""
    hosts, reason = rk.otx_hosts_from_body("<html>gateway timeout</html>")
    assert hosts is None and reason == ""
    hosts, reason = rk.otx_hosts_from_body("429 Too Many Requests")
    assert hosts is None and reason == "rate-limited"
    hosts, reason = rk.otx_hosts_from_body('{"passive_dns":[]}')
    assert hosts == [] and reason == ""
    hosts, reason = rk.otx_hosts_from_body('{"error":"too many requests"}')
    assert hosts is None and reason == "rate-limited"
    hosts, reason = rk.otx_hosts_from_body(
        '{"passive_dns":[{"hostname":"a.example.com"}]}'
    )
    assert hosts == ["a.example.com"] and reason == ""


def test_warn_uses_the_hud_slot() -> None:
    import reconkit as rk

    class Fake:
        def __init__(self) -> None:
            self._bar_open = True
            self._closed = False
            self._anim_lock = threading.Lock()

    fake = Fake()
    old_hud = ui._ACTIVE_HUD
    old_anim = ui.can_animate
    ui._ACTIVE_HUD = fake
    ui.can_animate = lambda: True
    try:
        text = _capture(lambda: rk.warn("findomain not found; skipping."))
    finally:
        ui._ACTIVE_HUD = old_hud
        ui.can_animate = old_anim
    assert text.startswith("\r\033[K")
    assert "\033[2K" not in text
    assert "[!]" in text
    assert "findomain not found; skipping." in text
    assert text.rstrip("\n").count("\n") == 0
    assert fake._bar_open is False


def main() -> None:
    try:
        test_finished_rows_count_up_and_the_spinner_does_not()
        test_summary_is_one_line()
        test_warning_takes_its_own_line()
        test_background_tty_prints_finish_rows_only()
        test_phase_end_leaves_one_completion_bar()
        test_probe_progress_records_each_host()
        test_http_probe_stream_splits_partial_lines()
        test_spinner_glyph_is_colored_when_color_is_on()
        test_spinner_stays_while_another_tool_runs()
        test_foreground_scan_drops_a_stale_background_flag()
        test_foreground_tty_still_animates()
        test_tool_timeout_clamps_and_rejects_junk()
        test_debug_lines_hide_the_chaos_key()
        test_otx_warns_only_on_a_refusal()
        test_warn_uses_the_hud_slot()
        print("ok")
    finally:
        shutil.rmtree(_HOME, ignore_errors=True)


if __name__ == "__main__":
    main()
