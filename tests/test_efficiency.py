"""Overlap, one dnsx pass, and one gf classification. No network."""

from __future__ import annotations

import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_pipe_rc_is_per_thread():
    import reconkit as rk

    barrier = threading.Barrier(2)
    seen: dict[int, int] = {}

    def worker(code: int) -> None:
        try:
            script = f"import sys; sys.exit({code})"
            rk.pipeline([[sys.executable, "-c", script]])
            seen[code] = int(rk._LAST_PIPE_RC)
        finally:
            try:
                barrier.wait(timeout=20)
            except Exception:
                pass

    threads = [threading.Thread(target=worker, args=(code,)) for code in (3, 4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert seen[3] == 3
    assert seen[4] == 4


def test_merge_names_keeps_unique_hosts():
    import reconkit as rk

    bag: set[str] = set()
    lock = threading.Lock()

    def add(i: int) -> None:
        rk.merge_names(
            bag,
            [f"h{i % 10}.example.com", f"only{i}.example.com"],
            lock,
        )

    threads = [threading.Thread(target=add, args=(i,)) for i in range(40)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(bag) == 50


def test_split_dnsx_records():
    import reconkit as rk

    text = "\n".join([
        "a.example.com [A] 1.2.3.4",
        "a.example.com [CNAME] old.github.io",
        "b.example.com [AAAA] ::1",
        "",
    ])
    resolved, records, cnames = rk.split_dnsx_records(text)
    assert resolved == ["a.example.com", "b.example.com"]
    assert len(records) == 3
    assert cnames == ["a.example.com [CNAME] old.github.io"]
    assert any(fp in cnames[0].lower() for fp in rk.CNAME_TAKEOVER_FINGERPRINTS)


def test_nuclei_pairs_share_the_profile_rate():
    import reconkit as rk

    assert rk.nuclei_worker_budget(0, 4, 150, 25) == (75, 12)
    assert rk.nuclei_worker_budget(3, 4, 150, 25) == (75, 12)
    assert rk.nuclei_worker_budget(0, 5, 150, 25) == (75, 12)
    assert rk.nuclei_worker_budget(4, 5, 150, 25) == (150, 25)
    assert rk.nuclei_worker_budget(0, 1, 150, 25) == (150, 25)
    assert rk.nuclei_worker_budget(0, 2, 50, 1) == (25, 1)


def test_httpprobe_runs_before_the_port_group():
    import reconkit as rk

    selected = [
        "subdomains", "dns", "ports", "httpprobe", "tls", "wellknown", "crawl", "js", "nuclei",
    ]
    groups = rk.execution_groups(selected)
    pos = {name: index for index, group in enumerate(groups) for name in group}
    assert pos["dns"] < pos["httpprobe"] < pos["ports"]
    assert pos["ports"] == pos["tls"] == pos["wellknown"] == pos["crawl"]
    assert pos["js"] > pos["crawl"]
    assert pos["nuclei"] > pos["js"]
    covered = rk.execution_groups(list(rk.ALL_MODULES))
    flat = [name for group in covered for name in group]
    assert len(flat) == len(set(flat)) == len(rk.ALL_MODULES)
    assert set(flat) == set(rk.ALL_MODULES)


def test_permute_does_not_resolve_when_dns_follows(tmp: Path):
    import reconkit as rk
    from hunter.stages import stage_permute

    subs = tmp / "subdomains.txt"
    subs.write_text("www.example.com\n", encoding="utf-8")
    orig_which = rk.which
    orig_pipe = rk.pipeline

    def boom(*_a, **_k):
        raise AssertionError("permute must not call dnsx when dns will run")

    rk.which = lambda _name: None
    rk.pipeline = boom
    try:
        stage_permute("example.com", tmp, resolve=False)
    finally:
        rk.which = orig_which
        rk.pipeline = orig_pipe
    assert subs.read_text(encoding="utf-8").strip() == "www.example.com"
    raw = (tmp / "permute_raw.txt").read_text(encoding="utf-8")
    assert "dev.example.com" in raw
    assert "dev.example.com" not in subs.read_text(encoding="utf-8")
    assert not (tmp / "permute_resolved.txt").exists()


def test_permute_resolves_itself_without_dns(tmp: Path):
    import reconkit as rk
    from hunter.stages import stage_permute

    subs = tmp / "subdomains.txt"
    subs.write_text("www.example.com\n", encoding="utf-8")
    calls: list[str] = []
    orig_which = rk.which
    orig_pipe = rk.pipeline

    def which(name: str):
        return "dnsx" if name == "dnsx" else None

    def pipe(commands, input_data=b"", timeout=None, on_stdout=None):
        calls.append(commands[0][0])
        return b"dev.example.com\n"

    rk.which = which
    rk.pipeline = pipe
    try:
        stage_permute("example.com", tmp, resolve=True)
    finally:
        rk.which = orig_which
        rk.pipeline = orig_pipe
    assert calls == ["dnsx"]
    text = subs.read_text(encoding="utf-8")
    assert "dev.example.com" in text
    assert "admin.example.com" not in text


def test_dns_is_one_pass_and_drops_unresolved_guesses(tmp: Path):
    import os
    import reconkit as rk

    os.environ["RECON_RESUME"] = "0"
    (tmp / "subdomains.txt").write_text("a.example.com\n", encoding="utf-8")
    (tmp / "permute_raw.txt").write_text(
        "dev.example.com\nguess.example.com\n", encoding="utf-8"
    )
    calls: list[list[str]] = []
    orig_which = rk.which
    orig_pipe = rk.pipe_into

    def which(name: str):
        return "dnsx" if name == "dnsx" else None

    def pipe(commands, input_data=b"", **kwargs):
        calls.append(list(commands[0]))
        assert b"dev.example.com" in input_data
        assert b"guess.example.com" in input_data
        body = (
            b"a.example.com [A] 1.2.3.4\n"
            b"dev.example.com [CNAME] old.github.io\n"
        )
        rk.save_tool_raw(kwargs["outdir"], kwargs["stage"], kwargs["tool"], body)
        rk._LAST_PIPE_RC.set(0)
        return body

    rk.which = which
    rk.pipe_into = pipe
    try:
        rk.stage_dns("example.com", tmp, tmp / "subdomains.txt")
    finally:
        rk.which = orig_which
        rk.pipe_into = orig_pipe
        os.environ.pop("RECON_RESUME", None)
    assert len(calls) == 1
    assert calls[0][0] == "dnsx"
    assert "-cname" in calls[0]
    resolved = (tmp / "resolved.txt").read_text(encoding="utf-8")
    assert "a.example.com" in resolved
    assert "dev.example.com" in resolved
    assert "guess.example.com" not in resolved
    subs = (tmp / "subdomains.txt").read_text(encoding="utf-8")
    assert "dev.example.com" in subs
    assert "guess.example.com" not in subs
    cname = (tmp / "cname_takeover_candidates.txt").read_text(encoding="utf-8")
    assert "github.io" in cname
    assert (tmp / "tools" / "dns" / "dnsx-resolved.txt").is_file()
    assert (tmp / "tools" / "dns" / "dnsx-cname.txt").is_file()


def test_gf_buckets_are_reused(tmp: Path):
    import reconkit as rk

    urls = tmp / "urls.txt"
    urls.write_text(
        "https://a.example.com/?q=1\nhttps://evil.test/?q=1\n",
        encoding="utf-8",
    )
    calls: list[str] = []
    lock = threading.Lock()
    orig_which = rk.which
    orig_pipe = rk.pipeline

    def which(name: str):
        return "gf" if name == "gf" else None

    def pipe(commands, input_data=b"", timeout=None, on_stdout=None):
        pat = commands[0][1]
        with lock:
            calls.append(pat)
        return f"https://a.example.com/?x={pat}\nhttps://evil.test/?x=1\n".encode()

    rk.which = which
    rk.pipeline = pipe
    try:
        rk.classify_urls(tmp, urls, "example.com", patterns=("xss", "sqli"))
        assert set(calls) == {"xss", "sqli"}
        text = (tmp / "gf_xss.txt").read_text(encoding="utf-8")
        assert "a.example.com" in text
        assert "evil.test" not in text
        done = len(calls)
        rk.classify_urls(tmp, urls, "example.com", patterns=("xss", "sqli"))
        assert len(calls) == done
        data, used = rk.gf_candidates(
            tmp, urls, "xss", "example.com", stage="xss", tool="gf",
        )
        assert used is True
        assert b"a.example.com" in data
        assert (tmp / "tools" / "xss" / "gf.txt").is_file()
        assert len(calls) == done
    finally:
        rk.which = orig_which
        rk.pipeline = orig_pipe


if __name__ == "__main__":
    import tempfile

    test_pipe_rc_is_per_thread()
    test_merge_names_keeps_unique_hosts()
    test_split_dnsx_records()
    test_nuclei_pairs_share_the_profile_rate()
    test_httpprobe_runs_before_the_port_group()
    with tempfile.TemporaryDirectory() as directory:
        test_permute_does_not_resolve_when_dns_follows(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_permute_resolves_itself_without_dns(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_dns_is_one_pass_and_drops_unresolved_guesses(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_gf_buckets_are_reused(Path(directory))
    print("ok")
