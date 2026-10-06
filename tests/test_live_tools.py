"""Caps, live tool files, host diff, and search. No network."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_tool_cap_clamps():
    import reconkit as rk

    os.environ["RECON_DNSX_TIMEOUT"] = "1"
    assert rk.tool_cap("dnsx") == 30
    os.environ["RECON_DNSX_TIMEOUT"] = "99999"
    assert rk.tool_cap("dnsx") == 1800
    os.environ["RECON_DNSX_TIMEOUT"] = "nope"
    assert rk.tool_cap("dnsx") == 300
    os.environ.pop("RECON_DNSX_TIMEOUT", None)


def test_interruptible_streams_and_caps():
    from run_control import run_interruptible

    chunks: list[bytes] = []
    proc = run_interruptible(
        [sys.executable, "-c", "print('hello', flush=True); import time; time.sleep(30)"],
        capture=True,
        timeout=2,
        on_stdout=chunks.append,
    )
    assert proc.returncode == 124
    assert b"hello" in (proc.stdout or b"")
    assert any(b"hello" in c for c in chunks)


def test_pipeline_keeps_partial_and_does_not_forward():
    import reconkit as rk

    one = rk.pipeline(
        [[sys.executable, "-c", "print('hello', flush=True); import time; time.sleep(30)"]],
        timeout=2,
    )
    assert b"hello" in one
    assert rk._LAST_PIPE_RC == 124

    blocked = rk.pipeline(
        [
            [sys.executable, "-c", "import sys,time; sys.stdout.write('partial'); sys.stdout.flush(); time.sleep(30)"],
            [sys.executable, "-c", "print('SHOULD_NOT')"],
        ],
        timeout=2,
    )
    assert b"SHOULD_NOT" not in blocked
    assert rk._LAST_PIPE_RC == 124


def test_live_tool_file_and_drops(tmp_path: Path):
    import reconkit as rk

    rk.reset_run_bookkeeping()
    live = rk.LiveToolFile(tmp_path, "dns", "dnsx-records")
    live.write(b"a.example.com\n")
    live.write(b"b.example.com\n")
    live.close()
    live.close()
    assert "a.example.com" in live.path.read_text(encoding="utf-8")
    rk.save_tool_raw(tmp_path, "dns", "dnsx-records", "a.example.com\n")
    assert live.path.read_text(encoding="utf-8").strip() == "a.example.com"

    rk.note_dropped(tmp_path, "subdomains", "out-of-scope", "evil.test")
    dropped = (tmp_path / "tools" / "subdomains" / "dropped.txt").read_text(encoding="utf-8")
    assert "out-of-scope\tevil.test" in dropped


def test_resume_skip_respects_flag(tmp_path: Path):
    import reconkit as rk

    os.environ["RECON_RESUME"] = "0"
    rk.save_tool_raw(tmp_path, "dns", "dnsx-resolved", "a.example.com\n")
    assert rk.should_skip_tool(tmp_path, "dns", "dnsx-resolved", None) is False
    os.environ["RECON_RESUME"] = "1"
    assert rk.should_skip_tool(tmp_path, "dns", "dnsx-resolved", None) is True
    os.environ.pop("RECON_RESUME", None)


def test_host_diff_and_search(tmp_path: Path):
    import dashboard.outputs as out

    out.OUTPUT_DIR = tmp_path
    target = tmp_path / "example.com"
    target.mkdir()
    (target / "subdomains.txt").write_text(
        "a.example.com\nb.example.com\n", encoding="utf-8", newline="\n"
    )
    (target / "subdomains.txt.prev").write_text(
        "a.example.com\nold.example.com\n", encoding="utf-8", newline="\n"
    )
    (target / "urls.txt").write_text("https://a.example.com/\n", encoding="utf-8", newline="\n")
    diff = out.diff_host_file("example.com", "subdomains.txt")
    assert diff["ok"] is True
    assert diff["new"] == ["b.example.com"]
    assert diff["gone"] == ["old.example.com"]
    fresh = out.diff_host_file("example.com", "urls.txt")
    assert fresh["has_prev"] is False
    assert fresh["new"] == []
    bad = out.diff_host_file("example.com", "../secrets.txt")
    assert bad["ok"] is False
    hits = out.search_output("example.com", "old.example")
    assert hits["ok"] is True
    assert any("old.example.com" in h["text"] for h in hits["hits"])
    outside = out.search_output("..", "a")
    assert outside["ok"] is False


def test_param_priority_and_routes(tmp_path: Path):
    import reconkit as rk

    (tmp_path / "param_names.txt").write_text("id\ncolor\nredirect_uri\n", encoding="utf-8")
    (tmp_path / "xss_reflected_params.txt").write_text(
        "https://a.example.com/?id=1\n", encoding="utf-8"
    )
    (tmp_path / "alive.txt").write_text(
        "https://a.example.com [200] [Grafana]\n", encoding="utf-8"
    )
    rk.write_param_priority(tmp_path)
    text = (tmp_path / "param_priority.txt").read_text(encoding="utf-8")
    assert "redirect_uri" in text
    assert "\nid\n" in text or text.startswith("id\n") or "\nid\n" in ("\n" + text)
    assert "color" not in text
    rk.write_tech_routes(tmp_path)
    routes = (tmp_path / "tech_routes.txt").read_text(encoding="utf-8")
    assert "nuclei_recheck" in routes
    assert "xss_reflect" in routes


if __name__ == "__main__":
    test_tool_cap_clamps()
    test_interruptible_streams_and_caps()
    test_pipeline_keeps_partial_and_does_not_forward()
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        test_live_tool_file_and_drops(p)
    with tempfile.TemporaryDirectory() as d:
        test_resume_skip_respects_flag(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_host_diff_and_search(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_param_priority_and_routes(Path(d))
    print("ok")
