"""Prompt payloads stay short and follow file counts. No network."""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_brief_skips_empty_inputs_and_keeps_ports(tmp: Path):
    from agents.state import recon_brief

    (tmp / "subdomains.txt").write_text("a.example.com\nb.example.com\n", encoding="utf-8")
    (tmp / "alive.txt").write_text("\n", encoding="utf-8")
    (tmp / "urls.txt").write_text("", encoding="utf-8")
    (tmp / "cname_takeover_candidates.txt").write_text(
        "dev.example.com [CNAME] x.github.io\n",
        encoding="utf-8",
    )
    brief = recon_brief(
        tmp,
        ["dns", "xss", "crawl", "graphql", "takeover_plus", "ports"],
    )
    assert "subdomains.txt=2" in brief
    assert "alive.txt=0" in brief
    assert "urls.txt=0" in brief
    assert "cname_takeover_candidates.txt=1" in brief
    skip = _skip_names(brief)
    for name in ("xss", "crawl", "graphql", "takeover_plus"):
        assert name in skip
    assert "dns" not in skip
    assert "ports" not in skip
    assert "github.io" in brief
    assert "outranks another crawl" not in brief


def test_brief_does_not_copy_url_bodies(tmp: Path):
    from agents.state import recon_brief

    (tmp / "alive.txt").write_text("https://app.example.com [200]\n", encoding="utf-8")
    (tmp / "urls.txt").write_text(
        "https://app.example.com/graphql?q=1 UNIQUEURLTOKEN\n",
        encoding="utf-8",
    )
    brief = recon_brief(tmp, ["graphql", "xss", "crawl"])
    assert "graphql" not in _skip_names(brief)
    assert "xss" not in _skip_names(brief)
    assert "UNIQUEURLTOKEN" not in brief
    assert "https://app.example.com [200]" in brief


def test_brief_skips_graphql_without_a_token(tmp: Path):
    from agents.state import recon_brief

    (tmp / "alive.txt").write_text("https://app.example.com [200] [nginx]\n", encoding="utf-8")
    (tmp / "urls.txt").write_text("https://app.example.com/home\n", encoding="utf-8")
    (tmp / "cname_takeover_candidates.txt").write_text(
        "dev.example.com [CNAME] x.github.io\n",
        encoding="utf-8",
    )
    brief = recon_brief(tmp, ["graphql", "xss", "takeover_plus"])
    skip = _skip_names(brief)
    assert skip == ["graphql"]
    assert "outranks another crawl" in brief
    assert "Do not pick dns again" in brief


def test_nuclei_head_keeps_severity_lines(tmp: Path):
    from agents.state import recon_brief

    (tmp / "alive.txt").write_text("https://app.example.com\n", encoding="utf-8")
    (tmp / "urls.txt").write_text("https://app.example.com/\n", encoding="utf-8")
    (tmp / "nuclei_cve.txt").write_text(
        "info chatter UNIQUE_NOISE\n[critical] https://app.example.com/panel\n",
        encoding="utf-8",
    )
    brief = recon_brief(tmp, ["nuclei"])
    assert "nuclei_files=1" in brief
    assert "[critical]" in brief
    assert "UNIQUE_NOISE" not in brief
    assert "nuclei" not in _skip_names(brief)


def test_planner_user_is_counts_not_a_dump(tmp: Path):
    from agents.specialists import planner_messages
    from agents.state import ReconState

    (tmp / "subdomains.txt").write_text("a.example.com\n", encoding="utf-8")
    state = ReconState(target="example.com", outdir=str(tmp))
    state.completed_modules = ["subdomains", "httpprobe", "crawl"]
    messages = planner_messages(state, ["xss", "graphql", "nuclei"])
    system = messages[0]["content"]
    user = messages[1]["content"]
    assert "MODULE_DESCRIPTIONS" not in user
    assert "subfinder, amass" not in user
    assert "history" not in user
    assert "skip_if_chosen" in user
    assert "xss" in _skip_names(user)
    assert "owners:" in user
    assert len(user) < 2500
    assert "File counts and heads outrank" in system
    assert "sqlmap" in system
    assert '"done":false' in system


def test_tool_lines_drop_previews():
    from agents.specialists import tool_result_lines

    text = tool_result_lines([
        {
            "module": "dns",
            "success": True,
            "outputs": [{
                "path": "dns_records.txt",
                "exists": True,
                "lines": 3,
                "preview": "SECRETPREVIEW should not enter the prompt",
                "interesting_keywords": ["takeover"],
            }],
        }
    ])
    assert "dns_records.txt=3" in text
    assert "takeover" in text
    assert "SECRETPREVIEW" not in text


def test_evidence_is_a_short_head(tmp: Path):
    from agents.state import analyst_evidence

    (tmp / "urls.txt").write_text("UNIQUEURLTOKEN\n" * 20, encoding="utf-8")
    (tmp / "cname_takeover_candidates.txt").write_text(
        "\n".join(f"h{i}.example.com" for i in range(10)) + "\n",
        encoding="utf-8",
    )
    text = analyst_evidence(tmp)
    assert "UNIQUEURLTOKEN" not in text
    assert "h0.example.com" in text
    assert "h3.example.com" in text
    assert "h4.example.com" not in text


def test_review_prompts_keep_their_headings():
    from agents.critic import CRITIC_SYSTEM
    from agents.supervisor import _system_prompt, write_summary
    from dashboard.prompt import _messages

    prompt = _system_prompt(["xss_reflect", "cors_origin"])
    for heading in ("## Landed", "## Noise", "## Prove next", "## Ignore"):
        assert heading in prompt
    assert "xss_reflect" in prompt
    assert "You do not run tools" in prompt
    src = inspect.getsource(write_summary)
    assert "## Hunt note" in src
    assert "## Prove next" in src
    for heading in (
        "## Likely solid leads",
        "## Possible false positives",
        "## Missing checks",
        "## Suggested next modules",
    ):
        assert heading in CRITIC_SYSTEM
    messages = _messages("what next", "https://app.example.com", {"path": "alive.txt"})
    assert "not in the file" in messages[0]["content"]
    assert "sqlmap" in messages[0]["content"]
    assert "https://app.example.com" in messages[1]["content"]


def _skip_names(brief: str) -> list[str]:
    for line in brief.splitlines():
        if line.startswith("skip_if_chosen:"):
            return line.split(":", 1)[1].split()
    return []


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        test_brief_skips_empty_inputs_and_keeps_ports(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_brief_does_not_copy_url_bodies(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_brief_skips_graphql_without_a_token(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_nuclei_head_keeps_severity_lines(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_planner_user_is_counts_not_a_dump(Path(directory))
    test_tool_lines_drop_previews()
    with tempfile.TemporaryDirectory() as directory:
        test_evidence_is_a_short_head(Path(directory))
    test_review_prompts_keep_their_headings()
    print("ok")
