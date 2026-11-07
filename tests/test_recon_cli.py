"""Root command rewriting. No scan, no network."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recon_entry", ROOT / "recon.py")
assert spec and spec.loader
recon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recon)


def test_bare_target_is_a_scan():
    kind, argv = recon.prepare(["example.com"])
    assert kind == "recon"
    assert argv == ["run", "--target", "example.com"]


def test_modules_resume_and_verbose():
    kind, argv = recon.prepare(
        ["example.com", "dns,httpprobe", "--resume", "-v", "2"]
    )
    assert kind == "recon"
    assert argv == [
        "-v", "2",
        "run", "--target", "example.com",
        "--modules", "dns,httpprobe",
        "--resume",
    ]


def test_long_form_still_works():
    kind, argv = recon.prepare(["run", "--target", "example.com", "--review"])
    assert kind == "recon"
    assert argv == ["run", "--target", "example.com", "--review"]


def test_run_accepts_a_positional_target():
    kind, argv = recon.prepare(["run", "example.com", "--review"])
    assert kind == "recon"
    assert argv == ["run", "--target", "example.com", "--review"]


def test_findings_and_prove_shortcuts():
    kind, argv = recon.prepare(["findings", "example.com"])
    assert (kind, argv) == ("recon", ["findings", "summary", "example.com"])
    kind, argv = recon.prepare(["prove", "example.com", "xss_reflect"])
    assert argv == [
        "prove", "run", "--target", "example.com", "--technique", "xss_reflect",
    ]


def test_agents_list_and_scan():
    assert recon.prepare(["agents"]) == ("agents", ["agents"])
    kind, argv = recon.prepare(["agents", "example.com", "xss"])
    assert kind == "agents"
    assert argv == ["run", "--target", "example.com", "--modules", "xss"]


def test_unknown_command():
    kind, argv = recon.prepare(["frobnicate"])
    assert kind == "error"
    assert "frobnicate" in argv[0]


def test_help_and_empty():
    assert recon.prepare([])[0] == "usage"
    assert recon.prepare(["--help"])[0] == "usage"
    assert recon.prepare(["help", "run"]) == ("help", ["run"])


if __name__ == "__main__":
    test_bare_target_is_a_scan()
    test_modules_resume_and_verbose()
    test_long_form_still_works()
    test_run_accepts_a_positional_target()
    test_findings_and_prove_shortcuts()
    test_agents_list_and_scan()
    test_unknown_command()
    test_help_and_empty()
    print("ok")
