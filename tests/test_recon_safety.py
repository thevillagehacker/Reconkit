"""Default modules, asset diff, and fetch guards. No network and no scan."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def test_default_modules_are_the_passive_set():
    import reconkit

    assert reconkit.resolve_modules(None) == reconkit.DEFAULT_MODULES
    assert reconkit.resolve_modules("default") == [
        "subdomains", "dns", "httpprobe", "tls", "wellknown", "crawl",
    ]
    assert reconkit.resolve_modules("all") == reconkit.ALL_MODULES
    assert reconkit.resolve_modules("dns,httpprobe") == ["dns", "httpprobe"]
    parser = reconkit.build_parser()
    args = parser.parse_args(["run", "--target", "example.com"])
    assert args.modules == "default"
    assert reconkit.resolve_modules(args.modules) == reconkit.DEFAULT_MODULES


def test_asset_diff_highlights_only_changes(tmp: Path):
    import reconkit

    reconkit.write_host_list(tmp / "subdomains.txt", ["a.example.com", "b.example.com"])
    reconkit.update_asset_diff(tmp, "subdomains.txt")
    first = json.loads((tmp / "diff_assets.json").read_text(encoding="utf-8"))
    assert first["files"]["subdomains.txt"]["first_run"] is True
    assert first["files"]["subdomains.txt"]["new"] == []

    reconkit.snapshot_prev(tmp / "subdomains.txt")
    reconkit.write_host_list(tmp / "subdomains.txt", ["a.example.com", "c.example.com"])
    (tmp / "diff_assets.md").write_text("# old\n", encoding="utf-8")
    reconkit.update_asset_diff(tmp, "subdomains.txt")
    second = json.loads((tmp / "diff_assets.json").read_text(encoding="utf-8"))
    section = second["files"]["subdomains.txt"]
    assert section["first_run"] is False
    assert section["new"] == ["c.example.com"]
    assert section["removed"] == ["b.example.com"]
    assert not (tmp / "diff_assets.md").exists()


def test_httpx_line_keeps_status_title_and_hash():
    import reconkit

    row = reconkit.parse_httpx_line(
        "https://app.example.com [200] [App] [nginx] [a] [0123456789abcdef0123456789abcdef]"
    )
    assert row["url"] == "https://app.example.com"
    assert row["status"] == 200
    assert row["title"] == "App"
    assert "nginx" in row["tech"]
    assert row["body_hash"] == "0123456789abcdef0123456789abcdef"


def test_one_passive_source_failure_keeps_the_other():
    import reconkit

    kept: list[str] = []

    def good() -> None:
        kept.append("crt.sh")

    def bad() -> None:
        raise RuntimeError("rate limit")

    errors = reconkit.run_named_jobs([("crt.sh", good), ("otx", bad)])
    assert kept == ["crt.sh"]
    assert len(errors) == 1
    assert errors[0].startswith("otx:")


def test_metadata_and_off_target_fetches_are_refused():
    from prove.http_util import fetch_block_reason, http_get

    meta = http_get("http://169.254.169.254/latest/meta-data/", timeout=1)
    assert meta["status"] is None
    assert "blocked" in meta["error"]
    assert fetch_block_reason("http://127.0.0.1/")
    assert fetch_block_reason("http://10.1.2.3/")
    from prove.http_util import _host_related
    assert fetch_block_reason("https://evil.com/x", scope_host="example.com")
    assert _host_related("example.com", "www.example.com")
    redirect = fetch_block_reason(
        "http://169.254.169.254/latest/meta-data/",
        scope_host="example.com",
    )
    assert redirect


def test_missing_httpx_keeps_alive(tmp: Path):
    import reconkit

    outdir = tmp / "example.com"
    outdir.mkdir()
    subs = outdir / "subdomains.txt"
    subs.write_text("a.example.com\n", encoding="utf-8")
    alive = outdir / "alive.txt"
    alive.write_text("https://a.example.com [200] [App]\nhttps://b.example.com [200] [Other]\n", encoding="utf-8")
    original = reconkit.which
    reconkit.which = lambda _name: None
    try:
        reconkit.stage_httpprobe(subs, outdir)
    finally:
        reconkit.which = original
    assert "a.example.com" in alive.read_text(encoding="utf-8")
    assert "b.example.com" in alive.read_text(encoding="utf-8")


def test_capped_probe_keeps_previous_alive(tmp: Path):
    import reconkit

    outdir = tmp / "example.com"
    outdir.mkdir()
    subs = outdir / "subdomains.txt"
    subs.write_text("a.example.com\nb.example.com\n", encoding="utf-8")
    alive = outdir / "alive.txt"
    alive.write_text("https://a.example.com [200] [App]\nhttps://b.example.com [200] [Other]\n", encoding="utf-8")
    original_which, original_pipe = reconkit.which, reconkit.pipe_into

    def pipe(*_args, **kwargs):
        reconkit._LAST_PIPE_RC.set(124)
        body = b"https://a.example.com [200] [App]\n"
        reconkit.save_tool_raw(kwargs["outdir"], "httpprobe", "httpx", body)
        reconkit.write_tool_rc(kwargs["outdir"], "httpprobe", "httpx", 124)
        return body

    reconkit.which = lambda name: "httpx" if name == "httpx" else None
    reconkit.pipe_into = pipe
    try:
        reconkit.stage_httpprobe(subs, outdir)
        partial = outdir / "tools" / "httpprobe" / "httpx.txt"
        assert partial.is_file()
        assert "a.example.com" in partial.read_text(encoding="utf-8")
        os.environ["RECON_RESUME"] = "1"
        assert reconkit.should_skip_tool(
            outdir, "httpprobe", "httpx", subs, canonical=alive,
        ) is False
    finally:
        reconkit.which = original_which
        reconkit.pipe_into = original_pipe
        os.environ.pop("RECON_RESUME", None)
    text = alive.read_text(encoding="utf-8")
    assert "a.example.com" in text
    assert "b.example.com" in text


def test_missing_crawlers_keep_urls(tmp: Path):
    import reconkit

    outdir = tmp / "example.com"
    outdir.mkdir()
    (outdir / "alive.txt").write_text("https://a.example.com\n", encoding="utf-8")
    urls = outdir / "urls.txt"
    urls.write_text("https://a.example.com/keep\n", encoding="utf-8")
    original = reconkit.which
    reconkit.which = lambda _name: None
    try:
        reconkit.stage_crawl(outdir / "alive.txt", outdir)
    finally:
        reconkit.which = original
    assert urls.read_text(encoding="utf-8") == "https://a.example.com/keep\n"
    assert not (outdir / "urls.txt.prev").exists()


def test_host_crawlers_do_not_share_one_log(tmp: Path):
    import reconkit

    outdir = tmp / "example.com"
    outdir.mkdir()
    (outdir / "alive.txt").write_text("https://a.example.com\nhttps://b.example.com\n", encoding="utf-8")
    original_which, original_run, original_pipe = reconkit.which, reconkit.run, reconkit.pipeline

    def which(name: str):
        return name if name in ("gospider", "hakrawler") else None

    def fake_run(cmd, **kwargs):
        assert kwargs.get("on_stdout") is None
        host = cmd[cmd.index("-s") + 1]
        code = 124 if "b.example.com" in host else 0

        class Proc:
            returncode = code
            stdout = f"{host}/page\n".encode()
            stderr = b""

        return Proc()

    def fake_pipeline(_commands, input_data=b"", timeout=None, on_stdout=None):
        assert on_stdout is None
        host = input_data.decode().strip()
        reconkit._LAST_PIPE_RC.set(0)
        return f"{host}/hk\n".encode()

    reconkit.which = which
    reconkit.run = fake_run
    reconkit.pipeline = fake_pipeline
    try:
        reconkit.stage_crawl(outdir / "alive.txt", outdir)
    finally:
        reconkit.which = original_which
        reconkit.run = original_run
        reconkit.pipeline = original_pipe
    gospider = (outdir / "tools" / "crawl" / "gospider.txt").read_text(encoding="utf-8")
    hakrawler = (outdir / "tools" / "crawl" / "hakrawler.txt").read_text(encoding="utf-8")
    assert "https://a.example.com/page" in gospider
    assert "https://b.example.com/page" in gospider
    assert "pagehttps://" not in gospider
    assert "https://a.example.com/hk" in hakrawler
    assert "https://b.example.com/hk" in hakrawler
    assert "hkhttps://" not in hakrawler
    os.environ["RECON_RESUME"] = "1"
    try:
        assert reconkit.should_skip_tool(outdir, "crawl", "gospider", outdir / "alive.txt") is False
    finally:
        os.environ.pop("RECON_RESUME", None)


def test_wildcard_drop_needs_the_same_body_hash(tmp: Path):
    import reconkit

    outdir = tmp / "wild.example.com"
    outdir.mkdir()
    same = "a" * 64
    other = "b" * 64
    (outdir / "wildcard_dns.txt").write_text("rk-wc.wild.example.com\n", encoding="utf-8")
    alive = outdir / "alive.txt"
    alive.write_text(
        "\n".join([
            f"https://wild.example.com [403] [Forbidden] [{same}]",
            f"https://app.wild.example.com [403] [Forbidden] [{other}]",
            f"https://sink.wild.example.com [403] [Forbidden] [{same}]",
            "https://plain.wild.example.com [403] [Forbidden]",
        ]) + "\n",
        encoding="utf-8",
    )
    original_which, original_pipe = reconkit.which, reconkit.pipeline

    def fake_pipeline(*_args, **_kwargs):
        return f"https://rk-wc.wild.example.com [403] [Forbidden] [{same}]\n".encode()

    reconkit.which = lambda name: "httpx" if name == "httpx" else None
    reconkit.pipeline = fake_pipeline
    try:
        reconkit._filter_wildcard_http(alive, outdir, "wild.example.com")
    finally:
        reconkit.which = original_which
        reconkit.pipeline = original_pipe
    text = alive.read_text(encoding="utf-8")
    assert "https://wild.example.com" in text
    assert "app.wild.example.com" in text
    assert "plain.wild.example.com" in text
    assert "sink.wild.example.com" not in text


def test_finished_probe_is_stored_once(tmp: Path):
    import reconkit

    outdir = tmp / "example.com"
    outdir.mkdir()
    subs = outdir / "subdomains.txt"
    subs.write_text("a.example.com\n", encoding="utf-8")
    (outdir / "alive_urls.txt").write_text("https://stale.example.com\n", encoding="utf-8")
    (outdir / "httpprobe.json").write_text("{}\n", encoding="utf-8")
    original_which, original_pipe = reconkit.which, reconkit.pipe_into

    def pipe(*_args, **kwargs):
        reconkit._LAST_PIPE_RC.set(0)
        body = b"https://a.example.com [200] [App]\n"
        reconkit.save_tool_raw(kwargs["outdir"], "httpprobe", "httpx", body)
        reconkit.write_tool_rc(kwargs["outdir"], "httpprobe", "httpx", 0)
        return body

    reconkit.which = lambda name: "httpx" if name == "httpx" else None
    reconkit.pipe_into = pipe
    try:
        reconkit.stage_httpprobe(subs, outdir)
        alive = outdir / "alive.txt"
        assert "a.example.com" in alive.read_text(encoding="utf-8")
        assert not (outdir / "tools" / "httpprobe" / "httpx.txt").exists()
        rc = (outdir / "tools" / "httpprobe" / "httpx.txt.rc").read_text(encoding="utf-8")
        assert rc.strip() == "0"
        assert not (outdir / "alive_urls.txt").exists()
        assert not (outdir / "httpprobe.json").exists()
        os.environ["RECON_RESUME"] = "1"
        assert reconkit.should_skip_tool(
            outdir, "httpprobe", "httpx", subs, canonical=alive,
        ) is True
        reconkit.stage_httpprobe(subs, outdir)
        assert "a.example.com" in alive.read_text(encoding="utf-8")
    finally:
        reconkit.which = original_which
        reconkit.pipe_into = original_pipe
        os.environ.pop("RECON_RESUME", None)


def test_review_samples_the_root_file_once(tmp: Path):
    from agents.supervisor import _collect

    outdir = tmp / "example.com"
    (outdir / "tools" / "httpprobe").mkdir(parents=True)
    (outdir / "alive.txt").write_text("https://a.example.com [200]\n", encoding="utf-8")
    (outdir / "tools" / "httpprobe" / "httpx.txt").write_text(
        "https://a.example.com [200]\n", encoding="utf-8",
    )
    samples, _dropped_lines, _dropped_count, _omitted, _context = _collect(outdir, "httpprobe")
    rels = [sample.rel.replace("\\", "/") for sample in samples]
    assert rels == ["alive.txt"]


def test_output_path_cannot_escape():
    import reconkit

    for raw in ("..", "."):
        try:
            reconkit.output_dir_for(raw)
        except ValueError:
            continue
        raise AssertionError(f"escaped output path was accepted: {raw}")


if __name__ == "__main__":
    import tempfile

    test_default_modules_are_the_passive_set()
    test_httpx_line_keeps_status_title_and_hash()
    test_one_passive_source_failure_keeps_the_other()
    test_metadata_and_off_target_fetches_are_refused()
    test_output_path_cannot_escape()
    with tempfile.TemporaryDirectory() as directory:
        test_asset_diff_highlights_only_changes(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_missing_httpx_keeps_alive(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_capped_probe_keeps_previous_alive(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_finished_probe_is_stored_once(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_review_samples_the_root_file_once(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_missing_crawlers_keep_urls(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_host_crawlers_do_not_share_one_log(Path(directory))
    with tempfile.TemporaryDirectory() as directory:
        test_wildcard_drop_needs_the_same_body_hash(Path(directory))
    print("ok")
