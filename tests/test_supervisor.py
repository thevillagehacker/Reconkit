"""Opt-in phase reviewer. No network."""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PHASE_OK = (
    "## Landed\nreal hit\n## Noise\nn\n"
    "## Prove next\nsqlmap\nxss_reflect\n## Ignore\ni\n"
)


@contextmanager
def env(**kwargs):
    old = {key: os.environ.get(key) for key in kwargs}
    for key, value in kwargs.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _phase_dir(tmp: Path, phase: str = "dns") -> Path:
    folder = tmp / "tools" / phase
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def test_disabled_schedule_writes_nothing(tmp: Path):
    from agents.supervisor import schedule_phase_review

    with env(RECON_SUPERVISOR=None):
        assert schedule_phase_review(tmp, "dns", chat=lambda _m: "nope") is False
    assert not (tmp / "reviews").exists()


def test_facts_budget_and_prove_constraint(tmp: Path):
    from agents.supervisor import review_phase

    folder = _phase_dir(tmp, "xss")
    lines = [f"host{i}.example.com" for i in range(80)]
    (folder / "kxss.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (folder / "dropped.txt").write_text("scope\tout\n", encoding="utf-8")
    seen: dict[str, str] = {}

    def chat(messages):
        seen["body"] = messages[-1]["content"]
        return "## Landed\nuse sqlmap now\nreal hit\n## Noise\nn\n## Prove next\nsqlmap\nxss_reflect\n## Ignore\ni\n"

    path = review_phase(tmp, "xss", chat=chat, resume=False)
    assert path is not None
    body = seen["body"]
    assert "80 lines" in body
    assert "host0.example.com" in body
    assert "host29.example.com" in body
    assert "host30.example.com" not in body
    assert "scope\tout" in body
    text = path.read_text(encoding="utf-8")
    facts = text.split("## Landed")[0]
    assert "80 lines" in facts
    assert "9999" not in facts
    assert "sqlmap" not in text.lower()
    assert "real hit" in text
    assert "xss_reflect" in text
    assert "# status=ok" in text
    assert "# lines=80" in text
    assert "# prove_constrained=1" in text
    assert "\r" not in text


def test_failing_chat_keeps_facts_and_hides_secrets(tmp: Path):
    from agents.supervisor import review_phase

    folder = _phase_dir(tmp)
    (folder / "dnsx.txt").write_text("a.example.com\n\nb.example.com\n", encoding="utf-8")

    def chat(_messages):
        raise RuntimeError("bad key xai-secretvalue")

    path = review_phase(tmp, "dns", chat=chat, resume=False)
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert "# status=skipped" in text
    assert "2 lines" in text
    assert "xai-secretvalue" not in text
    assert "xai-***" in text


def test_empty_phase_skips_model(tmp: Path):
    from agents.supervisor import review_phase

    def chat(_messages):
        raise AssertionError("model called")

    path = review_phase(tmp, "ports", chat=chat, resume=False)
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert "# status=empty" in text
    assert "total: 0 lines" in text


def test_resume_skips_fresh_note_and_reruns_when_tools_are_newer(tmp: Path):
    from agents.supervisor import review_phase

    folder = _phase_dir(tmp)
    tool = folder / "dnsx.txt"
    tool.write_text("a.example.com\n", encoding="utf-8")
    note = tmp / "reviews" / "dns.txt"
    note.parent.mkdir(parents=True)
    note.write_text("KEEP\n", encoding="utf-8")
    now = time.time()
    os.utime(tool, (now - 100, now - 100))
    os.utime(note, (now, now))

    def boom(_messages):
        raise AssertionError("model called")

    assert review_phase(tmp, "dns", chat=boom, resume=True) is None
    assert note.read_text(encoding="utf-8") == "KEEP\n"

    os.utime(tool, (now + 50, now + 50))
    path = review_phase(tmp, "dns", chat=lambda _m: PHASE_OK, resume=True)
    assert path == note
    text = note.read_text(encoding="utf-8")
    assert "KEEP" not in text
    assert "# status=ok" in text
    assert "xss_reflect" in text


def test_summary_commands_stay_inside_prove(tmp: Path):
    from agents.supervisor import wait_and_summarize, write_summary

    notes = tmp / "reviews"
    notes.mkdir()
    (notes / "dns.txt").write_text(
        "# status=ok\n# lines=1\n## Prove next\nxss_reflect\n",
        encoding="utf-8",
    )
    called: list[int] = []

    def chat(_messages):
        called.append(1)
        return "## Hunt note\nuse sqlmap\nlook at reflected\n## Prove next\nsqlmap\nxss_reflect\n"

    assert wait_and_summarize(tmp, "example.com", chat=chat, stopped=True) is None
    assert called == []
    assert not (notes / "summary.txt").exists()

    path = write_summary(tmp, "example.com", chat=chat)
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert "sqlmap" not in text.lower()
    assert "look at reflected" in text
    assert "/prove queue example.com" in text
    assert "/prove run example.com --technique xss_reflect" in text

    bad = write_summary(tmp, "example.com;id", chat=chat)
    assert bad is not None
    bad_text = bad.read_text(encoding="utf-8")
    assert "example.com;id" not in bad_text
    assert "# target=-" in bad_text
    assert "xss_reflect" in bad_text


def test_stop_does_not_start_or_call_the_model(tmp: Path):
    from agents import supervisor as sup

    folder = _phase_dir(tmp)
    (folder / "dnsx.txt").write_text("a.example.com\n", encoding="utf-8")
    with env(RECON_SUPERVISOR="1", RECON_RESUME=None):
        assert sup.schedule_phase_review(tmp, "dns", chat=lambda _m: "nope", stopped=True) is False
    assert not (tmp / "reviews").exists()
    called: list[int] = []
    sup._stop_fn = lambda: True
    try:
        path = sup.review_phase(tmp, "dns", chat=lambda _m: called.append(1), resume=False)
    finally:
        sup._stop_fn = None
    assert called == []
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert "# status=skipped" in text
    assert "reason=stopped" in text
    assert "1 lines" in text


def test_stale_run_does_not_overwrite(tmp: Path):
    from agents import supervisor as sup

    folder = _phase_dir(tmp)
    (folder / "dnsx.txt").write_text("a.example.com\n", encoding="utf-8")
    started = threading.Event()
    release = threading.Event()

    def chat(_messages):
        started.set()
        assert release.wait(3)
        return "## Landed\nSHOULD_NOT_LAND\n## Noise\nn\n## Prove next\nnone\n## Ignore\ni\n"

    with env(RECON_SUPERVISOR="1", RECON_RESUME=None):
        sup.begin_run(tmp)
        assert sup.schedule_phase_review(tmp, "dns", chat=chat) is True
        assert started.wait(3)
        thread = sup._inflight[0]
        sup.begin_run(tmp)
        release.set()
        thread.join(3)
        assert not thread.is_alive()
    assert not (tmp / "reviews" / "dns.txt").exists()


def test_review_flag_stays_on_its_thread():
    from agents.supervisor import bind_review, supervisor_enabled, unbind_review

    seen: dict[str, bool] = {}

    def other():
        seen["other"] = supervisor_enabled()

    with env(RECON_SUPERVISOR=None):
        assert not supervisor_enabled()
        prev = bind_review(True)
        try:
            assert supervisor_enabled()
            thread = threading.Thread(target=other)
            thread.start()
            thread.join(2)
            assert seen["other"] is False
        finally:
            unbind_review(prev)
        assert not supervisor_enabled()


def test_env_roundtrip_and_flags(tmp: Path):
    from agents.supervisor import pop_supervisor, push_supervisor, supervisor_enabled
    import reconkit as rk
    from shell.repl import ReconShell

    with env(RECON_SUPERVISOR=None):
        prev = push_supervisor(True)
        assert supervisor_enabled()
        pop_supervisor(prev)
        assert not supervisor_enabled()
        assert "RECON_SUPERVISOR" not in os.environ
        os.environ["RECON_SUPERVISOR"] = "0"
        prev = push_supervisor(True)
        assert os.environ["RECON_SUPERVISOR"] == "1"
        pop_supervisor(prev)
        assert os.environ["RECON_SUPERVISOR"] == "0"

    parser = rk.build_parser()
    assert parser.parse_args(["run", "--target", "example.com", "--review"]).review is True
    assert parser.parse_args(["run", "--target", "example.com", "--supervisor"]).review is True
    assert parser.parse_args(["run", "--target", "example.com"]).review is False

    shell = ReconShell(verbose=0, intro=False, target="example.com")
    parsed = shell._parse_run_args(["example.com", "--review", "--modules", "dns", "--fg"])
    assert parsed[0] == "example.com"
    assert parsed[1] == "dns"
    assert parsed[6] is True
    assert shell._parse_run_args(["--supervisor"])[6] is True

    with env(RECON_SUPERVISOR="1"):
        rk.write_run_meta(tmp, "example.com", ["dns"])
        meta = json.loads((tmp / "run_meta.json").read_text(encoding="utf-8"))
        assert meta["supervisor"] is True
        assert "cookie" not in json.dumps(meta).lower()
    with env(RECON_SUPERVISOR=None):
        rk.write_run_meta(tmp, "example.com", ["dns"])
        meta = json.loads((tmp / "run_meta.json").read_text(encoding="utf-8"))
        assert meta["supervisor"] is False


def test_dashboard_classifies_reviews():
    from dashboard.outputs import _classify

    assert _classify("reviews/dns.txt") == ("review", "dns", "review")
    assert _classify("reviews/summary.txt") == ("review", "summary", "review")


def test_unsafe_phase_name_is_rejected(tmp: Path):
    from agents.supervisor import review_phase

    def chat(_messages):
        raise AssertionError("model called")

    assert review_phase(tmp, "../secrets", chat=chat) is None
    assert review_phase(tmp, "summary", chat=chat) is None
    assert list(tmp.rglob("*")) == []


if __name__ == "__main__":
    import tempfile

    tests = [
        test_disabled_schedule_writes_nothing,
        test_facts_budget_and_prove_constraint,
        test_failing_chat_keeps_facts_and_hides_secrets,
        test_empty_phase_skips_model,
        test_resume_skips_fresh_note_and_reruns_when_tools_are_newer,
        test_summary_commands_stay_inside_prove,
        test_stop_does_not_start_or_call_the_model,
        test_stale_run_does_not_overwrite,
        test_env_roundtrip_and_flags,
        test_unsafe_phase_name_is_rejected,
    ]
    for test in tests:
        with tempfile.TemporaryDirectory() as folder:
            test(Path(folder))
    test_dashboard_classifies_reviews()
    test_review_flag_stays_on_its_thread()
    print("ok")
