"""Opt-in per-phase reviewer.

A normal scan never calls a model. With `--review` or `RECON_SUPERVISOR=1`,
each finished phase gets a short note under `reviews/<phase>.txt`. The note
is written from a daemon thread so the next module starts immediately.
`/stop` does not start a new model call and does not wait for one.

Line counts are computed here. Prove-next may name only techniques already
allowed by the prove policy, or `none`. This module does not run prove,
edit scope, or start a module.
"""

from __future__ import annotations

import os
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ChatFn = Callable[[list[dict[str, str]]], str]

_DEFAULT_TECHNIQUES = (
    "xss_reflect",
    "ssti_math",
    "nuclei_recheck",
    "takeover_fingerprint",
    "ssrf_canary_review",
    "sqli_boolean",
    "jwt_inspect",
    "cors_origin",
    "graphql_typename",
    "redirect_canary",
    "idor_session_diff",
)

# Merged filenames for a phase. Tool files under tools/<phase>/ are preferred.
# Kept here so the scan path does not import the dashboard.
_PHASE_MERGED: dict[str, tuple[str, ...]] = {
    "subdomains": ("subdomains.txt",),
    "permute": ("permute_raw.txt", "permute_resolved.txt"),
    "dns": (
        "resolved.txt",
        "dns_records.txt",
        "cname_takeover_candidates.txt",
        "wildcard_dns.txt",
    ),
    "ports": ("ports.txt", "ports_http.txt"),
    "httpprobe": (
        "alive.txt",
        "alive_urls.txt",
        "waf_detected.txt",
        "wildcard_http_dropped.txt",
    ),
    "tls": ("tls_recon.json",),
    "wellknown": ("wellknown.txt",),
    "crawl": ("urls.txt",),
    "js": ("js_urls.txt", "js_secrets_and_endpoints.json"),
    "jsintel": ("js_intel.json", "api_paths.txt"),
    "params": ("param_names.txt", "arjun_params.txt", "param_priority.txt"),
    "apis": ("api_urls.txt", "idor_candidates.txt"),
    "content": ("sensitive_paths_found.txt", "wordlist_target.txt"),
    "bypass403": ("bypass403.txt",),
    "gfextra": (
        "redirect_candidates.txt",
        "lfi_candidates.txt",
        "interesting_params.txt",
    ),
    "xss": ("xss_reflected_params.txt", "dalfox_results.txt"),
    "sqli": ("sqli_candidates.txt", "sqli_error_based.txt", "sqli_boolean_based.txt"),
    "ssrf_ssti": ("ssrf_metadata_candidates.txt", "ssti_candidates.txt"),
    "redirect": ("redirect_hits.txt",),
    "cors": ("cors_candidates.txt",),
    "graphql": ("graphql_endpoints.txt",),
    "cloud": ("cloud_assets.json", "open_s3_buckets.txt"),
    "takeover_plus": ("takeover_plus.txt",),
    "osint": ("osint.txt",),
    "gitrecon": ("git_urls.txt", "trufflehog.jsonl"),
}

_BINARY_SUFFIX = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip", ".gz", ".exe", ".dll",
}
_STOPWORDS = {
    "none", "the", "and", "for", "this", "that", "see", "run", "prove", "next",
    "technique", "techniques", "only", "with", "from", "file", "files", "no",
    "not", "candidate", "candidates", "review", "queue", "target", "phase",
    "note", "notes", "http", "https", "com", "txt", "line", "lines", "head",
}
_BANNED = (
    "sqlmap",
    "ghauri",
    "rce_shell",
    "credential_stuffing",
    "data_exfil",
    "reverse shell",
    "/bin/sh",
    "nc -e",
    "powershell -enc",
    "os.system",
)

_MAX_TOOL_FILES = 6
_MAX_MERGED = 4
_MAX_HEAD_LINES = 30
_MAX_HEAD_CHARS = 2500
_MAX_LINE_CHARS = 300
_MAX_PROMPT = 12000
_MAX_MODEL_CHARS = 4000
_MAX_DROPPED = 15
_MAX_CONTEXT_LINES = 40
_MAX_SUMMARY_NOTES = 8

_lock = threading.Lock()
_inflight: list[threading.Thread] = []
_gen = 0
_outdir_gen: dict[str, int] = {}
_slots = threading.Semaphore(2)
_tls = threading.local()
# Tests inject a stop predicate. Production reads run_control.
_stop_fn: Callable[[], bool] | None = None


def supervisor_enabled() -> bool:
    """True for an exported RECON_SUPERVISOR=1, or for this thread's --review run."""
    if os.environ.get("RECON_SUPERVISOR") == "1":
        return True
    return bool(getattr(_tls, "review", False))


def bind_review(enabled: bool) -> bool:
    """Turn notes on for this thread only. Returns the previous thread value."""
    prev = bool(getattr(_tls, "review", False))
    _tls.review = bool(enabled) or prev
    return prev


def unbind_review(prev: bool) -> None:
    _tls.review = bool(prev)


def supervisor_requested(flag: bool) -> bool:
    return bool(flag) or supervisor_enabled()


def push_supervisor(enabled: bool) -> str | None:
    """Remember the previous value. Set the flag only when this run wants notes."""
    prev = os.environ.get("RECON_SUPERVISOR")
    if enabled:
        os.environ["RECON_SUPERVISOR"] = "1"
    return prev


def pop_supervisor(prev: str | None) -> None:
    """Restore whatever the process had before this run, including an unset var."""
    if prev is None:
        os.environ.pop("RECON_SUPERVISOR", None)
    else:
        os.environ["RECON_SUPERVISOR"] = prev


def begin_run(outdir: Path) -> int:
    """Drop this target's previous in-flight notes from the join list."""
    global _gen
    key = _key(outdir)
    with _lock:
        _gen += 1
        _outdir_gen[key] = _gen
        _inflight.clear()
        return _gen


def schedule_phase_review(
    outdir: Path,
    phase: str,
    *,
    chat: ChatFn | None = None,
    resume: bool | None = None,
    stopped: bool | None = None,
) -> bool:
    """Start a daemon note for one finished phase. False when no thread starts."""
    if not supervisor_enabled():
        return False
    if stopped is None:
        stopped = _control_stopped()
    if stopped:
        return False
    phase_name = safe_phase(phase)
    if not phase_name:
        return False
    if resume is None:
        resume = os.environ.get("RECON_RESUME") == "1"
    if resume and _review_is_fresh(outdir, phase_name):
        _say(f"supervisor: keep reviews/{phase_name}.txt")
        return False
    root = Path(outdir)
    with _lock:
        gen = _outdir_gen.get(_key(root))
        _inflight[:] = [t for t in _inflight if t.is_alive()]

    def work() -> None:
        try:
            review_phase(
                root,
                phase_name,
                chat=chat,
                resume=False,
                gen=gen,
            )
        except Exception as exc:
            _say(f"supervisor: {phase_name} note failed ({_safe_reason(exc)})")

    # resume was already applied above. The worker must not skip a note that
    # this call just decided to write (the file is still the old one until then).
    thread = threading.Thread(
        target=work,
        name=f"recon-review-{phase_name}",
        daemon=True,
    )
    with _lock:
        _inflight.append(thread)
    thread.start()
    return True


def review_phase(
    outdir: Path,
    phase: str,
    *,
    chat: ChatFn | None = None,
    resume: bool | None = None,
    gen: int | None = None,
) -> Path | None:
    """Write one phase note. Returns the path, or None when the note was skipped."""
    phase_name = safe_phase(phase)
    if not phase_name:
        return None
    path = _review_path(outdir, phase_name)
    if path is None:
        return None
    if _generation_stale(outdir, gen):
        return None
    if resume is None:
        resume = os.environ.get("RECON_RESUME") == "1"
    if resume and _review_is_fresh(outdir, phase_name):
        return None
    try:
        return _review_phase(outdir, phase_name, path, chat=chat, gen=gen)
    except Exception as exc:
        if _generation_stale(outdir, gen):
            return None
        _write(
            path,
            f"# phase={phase_name}\n# status=skipped\n# reason={_safe_reason(exc)}\n",
        )
        _say(f"supervisor: wrote reviews/{phase_name}.txt (skipped)")
        return path


def wait_and_summarize(
    outdir: Path,
    target: str,
    *,
    chat: ChatFn | None = None,
    stopped: bool = False,
    join_timeout: float | None = None,
) -> Path | None:
    """Join in-flight notes, then write reviews/summary.txt. Stop skips both."""
    if stopped or _control_stopped():
        return None
    timeout = _join_timeout() if join_timeout is None else max(0.0, float(join_timeout))
    halted = _join(timeout)
    if halted or stopped or _control_stopped():
        return None
    return write_summary(outdir, target, chat=chat)


def write_summary(
    outdir: Path,
    target: str,
    *,
    chat: ChatFn | None = None,
) -> Path | None:
    path = _review_path(outdir, "summary", allow_summary=True)
    if path is None:
        return None
    notes = _phase_notes(outdir)
    if not notes:
        _write(path, "# status=empty\n# reason=no phase notes\n")
        _say("supervisor: wrote reviews/summary.txt (empty)")
        return path
    compiled = _compile_notes(notes)
    if "# status=ok" not in compiled:
        body = (
            "# status=skipped\n"
            "# reason=no phase produced a model note\n\n"
            + compiled
        )
        _write(path, body)
        _say("supervisor: wrote reviews/summary.txt (skipped)")
        return path
    allowed = _allowed_techniques()
    safe_target = _safe_target(target)
    shown_target = safe_target or "-"
    system = (
        "You summarize authorized recon phase notes for one target. "
        "You do not run tools, change scope, start modules, or exploit anything. "
        "Reply with exactly these headings: ## Hunt note, ## Prove next. "
        "Hunt note: at most 5 lines. Each line is one signal copied from the notes, with its phase file. "
        "Drop empty phases and repeated counts. "
        "Under Prove next, list only technique ids from this set, one per line, "
        f"or the single word none: {', '.join(allowed)}. "
        "Do not write shell commands."
    )
    user = f"Target: {shown_target}\n\n{compiled}"
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user[:_MAX_PROMPT]},
    ]
    try:
        with _model_slot():
            text, provider, model = _model_text(messages, chat)
    except Exception as exc:
        _write(
            path,
            "# status=skipped\n"
            f"# reason={_safe_reason(exc)}\n\n"
            + compiled,
        )
        _say("supervisor: wrote reviews/summary.txt (skipped)")
        return path
    hunt, prove_src, dropped = _split_summary(text, allowed)
    commands = _prove_commands(prove_src, safe_target)
    partial = _any_alive()
    header = [
        "# status=ok",
        f"# target={safe_target or '-'}",
        f"# provider={provider}",
        f"# model={model}",
        f"# phases={len(notes)}",
        f"# partial={1 if partial else 0}",
    ]
    if dropped:
        header.append("# prove_constrained=1")
    body = (
        "\n".join(header)
        + "\n\n"
        + compiled
        + "\n\n## Hunt note\n"
        + (hunt or "(none)")
        + "\n\n## Prove next\n"
        + "\n".join(commands)
        + "\n"
    )
    _write(path, body)
    _say("supervisor: wrote reviews/summary.txt (ok)")
    return path


def safe_phase(name: str, *, allow_summary: bool = False) -> str:
    n = (name or "").strip()
    if n.lower() == "summary":
        return "summary" if allow_summary else ""
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,40}", n):
        return n
    return ""


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


@dataclass
class _Sample:
    rel: str
    lines: int
    head: str
    binary: bool = False


def _review_phase(
    outdir: Path,
    phase: str,
    path: Path,
    *,
    chat: ChatFn | None,
    gen: int | None,
) -> Path | None:
    samples, dropped_lines, dropped_count, omitted, context = _collect(outdir, phase)
    facts = _facts(samples, dropped_count, omitted)
    total = sum(s.lines for s in samples)
    if _control_stopped():
        _write(path, _header(phase, "skipped", reason="stopped") + "\n" + facts + "\n")
        _say(f"supervisor: wrote reviews/{phase}.txt (skipped)")
        return path
    if total <= 0:
        _write(path, _header(phase, "empty", reason="no lines in phase output") + "\n" + facts + "\n")
        _say(f"supervisor: wrote reviews/{phase}.txt (empty)")
        return path
    if _generation_stale(outdir, gen):
        return None
    allowed = _allowed_techniques()
    excerpts = _excerpts(samples, dropped_lines, context)
    head = (
        f"Phase: {phase}\n"
        "Use the lines under the file heads. The Facts counts are final.\n\n"
        f"{facts}\n\n"
    )
    user = head + excerpts[: max(0, _MAX_PROMPT - len(head))]
    messages = [
        {"role": "system", "content": _system_prompt(allowed)},
        {"role": "user", "content": user},
    ]
    try:
        with _model_slot():
            if _generation_stale(outdir, gen):
                return None
            if _control_stopped():
                note = _header(
                    phase, "skipped", reason="stopped", files=len(samples), lines=total,
                )
                _write(path, note + "\n" + facts + "\n")
                _say(f"supervisor: wrote reviews/{phase}.txt (skipped)")
                return path
            text, provider, model = _model_text(messages, chat)
    except Exception as exc:
        if _generation_stale(outdir, gen):
            return None
        note = (
            _header(phase, "skipped", reason=_safe_reason(exc), files=len(samples), lines=total)
            + "\n"
            + facts
            + "\n"
        )
        _write(path, note)
        _say(f"supervisor: wrote reviews/{phase}.txt (skipped)")
        return path
    if _generation_stale(outdir, gen):
        return None
    landed, noise, prove, ignore, dropped_names = _split_phase(text, allowed)
    header = _header(
        phase,
        "ok",
        provider=provider,
        model=model,
        files=len(samples),
        lines=total,
        constrained=bool(dropped_names),
    )
    model_body = (
        f"## Landed\n{landed}\n\n"
        f"## Noise\n{noise}\n\n"
        f"## Prove next\n{prove}\n\n"
        f"## Ignore\n{ignore}\n"
    )
    _write(path, header + "\n" + facts + "\n\n" + model_body[:_MAX_MODEL_CHARS])
    _say(f"supervisor: wrote reviews/{phase}.txt (ok)")
    return path


def _system_prompt(allowed: list[str]) -> str:
    return (
        "You review one phase of an authorized recon scan. "
        "You do not run tools, change scope, start modules, or exploit anything. "
        "The Facts counts are already correct. Repeat a count only to point at a file. "
        "Use only hosts and URLs that appear in the excerpts. "
        "Reply in plain text with exactly these headings: "
        "## Landed, ## Noise, ## Prove next, ## Ignore. "
        "Landed: one line per host or URL that is new or high-signal, with the file name. "
        "Noise: empty, wildcard, or scanner-chatter lines. "
        "Under Prove next, list only technique ids from this set, one per line, "
        f"or the single word none: {', '.join(allowed)}. "
        "Ignore: files that should not drive the next step. "
        "Leave sqlmap, shells, and dumps out of the note. "
        "Keep each section to a few short lines."
    )


def _header(
    phase: str,
    status: str,
    *,
    reason: str = "",
    provider: str = "",
    model: str = "",
    files: int | None = None,
    lines: int | None = None,
    constrained: bool = False,
) -> str:
    rows = [f"# phase={phase}", f"# status={status}"]
    if reason:
        rows.append(f"# reason={reason}")
    if provider:
        rows.append(f"# provider={provider}")
    if model:
        rows.append(f"# model={model}")
    if files is not None:
        rows.append(f"# files={files}")
    if lines is not None:
        rows.append(f"# lines={lines}")
    if constrained:
        rows.append("# prove_constrained=1")
    return "\n".join(rows)


def _facts(samples: list[_Sample], dropped_count: int, omitted: int) -> str:
    rows = ["## Facts"]
    if not samples:
        rows.append("- (no phase files)")
    for sample in samples:
        if sample.binary:
            rows.append(f"- {sample.rel}: binary, skipped")
        else:
            rows.append(f"- {sample.rel}: {sample.lines} lines")
    total = sum(s.lines for s in samples)
    rows.append(f"- total: {total} lines")
    rows.append(f"- dropped: {dropped_count} lines")
    if omitted:
        rows.append(f"- files omitted from the sample: {omitted}")
    return "\n".join(rows)


def _excerpts(samples: list[_Sample], dropped_lines: list[str], context: list[tuple[str, str]]) -> str:
    parts: list[str] = []
    for sample in samples:
        if sample.binary or not sample.head:
            continue
        parts.append(f"### {sample.rel} ({sample.lines} lines, head)\n{sample.head}")
    if dropped_lines:
        parts.append("### dropped sample\n" + "\n".join(dropped_lines))
    for label, head in context:
        if head:
            parts.append(f"### {label} (context)\n{head}")
    return "\n\n".join(parts)


def _collect(
    outdir: Path,
    phase: str,
) -> tuple[list[_Sample], list[str], int, int, list[tuple[str, str]]]:
    root = Path(outdir)
    chosen: list[Path] = []
    names: set[str] = set()
    tool_root = root / "tools" / phase
    tool_files: list[Path] = []
    if tool_root.is_dir() and _inside(root, tool_root):
        for path in sorted(tool_root.iterdir()):
            if not path.is_file() or path.name == "dropped.txt":
                continue
            if path.name.endswith(".tmp"):
                continue
            if not _inside(root, path):
                continue
            tool_files.append(path)
    for path in tool_files[:_MAX_TOOL_FILES]:
        chosen.append(path)
        names.add(path.name)
    merged: list[Path] = []
    for name in _PHASE_MERGED.get(phase, ()):
        path = root / name
        if path.is_file() and path.name not in names and _inside(root, path):
            merged.append(path)
    if phase == "nuclei":
        for path in sorted(root.glob("nuclei_*.txt")):
            if path.is_file() and path.name not in names and _inside(root, path):
                merged.append(path)
    extra = merged[:_MAX_MERGED]
    for path in extra:
        names.add(path.name)
    chosen.extend(extra)
    omitted = max(0, len(tool_files) - _MAX_TOOL_FILES) + max(0, len(merged) - _MAX_MERGED)
    samples = [_sample(root, path) for path in chosen]
    dropped_count, dropped_lines = _dropped(root, phase)
    context: list[tuple[str, str]] = []
    for name in ("tech_routes.txt", "param_priority.txt"):
        path = root / name
        if path.is_file() and _inside(root, path):
            _lines, head = _head(path, _MAX_CONTEXT_LINES, 1500)
            if head:
                context.append((name, head))
    return samples, dropped_lines, dropped_count, omitted, context


def _sample(root: Path, path: Path) -> _Sample:
    rel = _rel(root, path)
    if path.suffix.lower() in _BINARY_SUFFIX or _looks_binary(path):
        return _Sample(rel=rel, lines=0, head="", binary=True)
    lines, head = _head(path, _MAX_HEAD_LINES, _MAX_HEAD_CHARS)
    return _Sample(rel=rel, lines=lines, head=head)


def _dropped(root: Path, phase: str) -> tuple[int, list[str]]:
    path = root / "tools" / phase / "dropped.txt"
    if not path.is_file() or not _inside(root, path):
        return 0, []
    lines, _head_text = _head(path, 10_000, 10_000_000)
    sample: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                text = raw.strip()
                if not text:
                    continue
                sample.append(text[:_MAX_LINE_CHARS])
                if len(sample) >= _MAX_DROPPED:
                    break
    except OSError:
        return lines, []
    return lines, sample


def _head(path: Path, max_lines: int, max_chars: int) -> tuple[int, str]:
    count = 0
    kept: list[str] = []
    size = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                text = raw.replace("\x00", "").rstrip("\r\n")
                if text.strip():
                    count += 1
                if len(kept) < max_lines and size < max_chars and text.strip():
                    piece = text[:_MAX_LINE_CHARS]
                    kept.append(piece)
                    size += len(piece) + 1
    except OSError:
        return 0, ""
    return count, "\n".join(kept)[:max_chars]


def _review_is_fresh(outdir: Path, phase: str) -> bool:
    path = _review_path(outdir, phase)
    if path is None or not path.is_file():
        return False
    try:
        if path.stat().st_size == 0:
            return False
        review_m = path.stat().st_mtime
    except OSError:
        return False
    newest = 0.0
    found = False
    for sample_path in _input_paths(outdir, phase):
        try:
            newest = max(newest, sample_path.stat().st_mtime)
            found = True
        except OSError:
            continue
    if not found:
        return True
    return review_m >= newest


def _input_paths(outdir: Path, phase: str) -> list[Path]:
    root = Path(outdir)
    found: list[Path] = []
    tool_root = root / "tools" / phase
    if tool_root.is_dir():
        for path in tool_root.iterdir():
            if path.is_file() and path.name != "dropped.txt":
                found.append(path)
    for name in _PHASE_MERGED.get(phase, ()):
        path = root / name
        if path.is_file():
            found.append(path)
    if phase == "nuclei":
        found.extend(p for p in root.glob("nuclei_*.txt") if p.is_file())
    return found


def _split_phase(text: str, allowed: list[str]) -> tuple[str, str, str, str, list[str]]:
    cleaned = _strip_fence(text)
    sections = _sections(cleaned)
    if not any(sections.values()):
        landed = _scrub(cleaned) or "(none)"
        return landed, "(none)", "none", "(none)", []
    landed = _scrub(sections.get("landed", "")) or "(none)"
    noise = _scrub(sections.get("noise", "")) or "(none)"
    ignore = _scrub(sections.get("ignore", "")) or "(none)"
    names, dropped = _prove_names(sections.get("prove next", ""), allowed)
    prove = "\n".join(names) if names else "none"
    return landed, noise, prove, ignore, dropped


def _split_summary(text: str, allowed: list[str]) -> tuple[str, list[str], list[str]]:
    sections = _sections(_strip_fence(text))
    hunt = _scrub(sections.get("hunt note", ""))
    names, dropped = _prove_names(sections.get("prove next", ""), allowed)
    return hunt[:2000], names, dropped


def _prove_names(section: str, allowed: list[str]) -> tuple[list[str], list[str]]:
    allowed_set = {a.lower() for a in allowed}
    found: list[str] = []
    dropped: list[str] = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9_]{1,40}", section or ""):
        low = token.lower()
        if low in _STOPWORDS:
            continue
        if low in allowed_set:
            if low not in found:
                found.append(low)
            continue
        if low not in dropped:
            dropped.append(low)
    return found, dropped


def _prove_commands(names: list[str], target: str) -> list[str]:
    if not names:
        return ["none"]
    if not target:
        return list(names)
    lines = [f"/prove queue {target}"]
    lines.extend(f"/prove run {target} --technique {name}" for name in names)
    return lines


def _sections(text: str) -> dict[str, str]:
    wanted = {"landed", "noise", "prove next", "ignore", "hunt note"}
    current = ""
    buckets: dict[str, list[str]] = {key: [] for key in wanted}
    for line in (text or "").splitlines():
        match = re.match(r"^#{1,3}\s*(.+?)\s*$", line.strip())
        if match:
            title = match.group(1).strip().lower()
            if title in buckets:
                current = title
                continue
        if current:
            buckets[current].append(line)
    return {key: "\n".join(rows).strip() for key, rows in buckets.items()}


def _scrub(text: str) -> str:
    if not text:
        return ""
    banned = _banned_re()
    kept = [line for line in text.splitlines() if line.strip() and not banned.search(line)]
    return "\n".join(kept).strip()[:_MAX_MODEL_CHARS]


def _banned_re() -> re.Pattern[str]:
    parts = [re.escape(word) for word in _BANNED if word]
    return re.compile("|".join(parts), re.IGNORECASE)


def _strip_fence(text: str) -> str:
    body = (text or "").strip()
    body = re.sub(r"^```[a-zA-Z0-9]*\n", "", body)
    body = re.sub(r"\n```$", "", body)
    return body.strip()


def _compile_notes(notes: list[Path]) -> str:
    ranked = sorted(notes, key=lambda p: (0 if _status_ok(p) else 1, p.name))
    picked = ranked[:_MAX_SUMMARY_NOTES]
    parts = [f"## Phase notes ({len(notes)} files, {len(picked)} shown)"]
    for path in picked:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        parts.append(f"### {path.name}\n{text[:1500]}")
    omitted = len(notes) - len(picked)
    if omitted:
        parts.append(f"- phase notes omitted from the sample: {omitted}")
    return "\n\n".join(parts)


def _status_ok(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            head = handle.read(200)
    except OSError:
        return False
    return "# status=ok" in head


def _phase_notes(outdir: Path) -> list[Path]:
    folder = Path(outdir) / "reviews"
    if not folder.is_dir():
        return []
    notes: list[Path] = []
    for path in sorted(folder.glob("*.txt")):
        if path.name in {"summary.txt"} or path.name.endswith(".tmp"):
            continue
        if path.is_file():
            notes.append(path)
    return notes


def _model_text(messages: list[dict[str, str]], chat: ChatFn | None) -> tuple[str, str, str]:
    if chat is not None:
        text = chat(messages)
        if not str(text or "").strip():
            raise RuntimeError("empty model reply")
        return str(text), "test", "injected"
    from agents.llm import LLMError

    client = _review_client()
    provider = client.config.provider or "unknown"
    model = client.config.model or "unknown"
    if provider != "ollama" and not (client.config.api_key or "").strip():
        raise LLMError(f"no API key for {provider}")
    text = client.chat(messages, temperature=0.1)
    if not (text or "").strip():
        raise LLMError("empty model reply")
    return text, provider, model


def _review_client():
    from agents.llm import LLMClient, LLMConfig

    base = LLMClient().config
    timeout = min(int(base.timeout or 45), _env_int("RECON_SUPERVISOR_TIMEOUT", 45, 10, 120))
    cfg = LLMConfig(
        provider=base.provider,
        model=base.model,
        base_url=base.base_url,
        api_key=base.api_key,
        temperature=0.1,
        timeout=timeout,
        use_openai_compat=base.use_openai_compat,
    )
    return LLMClient(cfg)


def _allowed_techniques() -> list[str]:
    try:
        from prove.policy import load_policy

        raw = load_policy().get("allowed_techniques") or []
        names = []
        for item in raw:
            name = str(item).strip()
            if name and name not in names:
                names.append(name)
        if names:
            return names
    except Exception:
        pass
    return list(_DEFAULT_TECHNIQUES)


def _safe_target(target: str) -> str:
    text = (target or "").strip()
    if re.fullmatch(r"[A-Za-z0-9._*-]{1,253}", text):
        return text
    return ""


def _safe_reason(exc: BaseException) -> str:
    message = f"{type(exc).__name__}: {exc}"
    message = re.sub(r"(xai-|sk-|Bearer\s+)\S+", r"\1***", message, flags=re.IGNORECASE)
    message = re.sub(r"(api_key=)\S+", r"\1***", message, flags=re.IGNORECASE)
    return message.replace("\n", " ").replace("\r", " ")[:200]


def _control_stopped() -> bool:
    if _stop_fn is not None:
        return bool(_stop_fn())
    try:
        from run_control import CONTROL

        return bool(CONTROL.is_stopped())
    except Exception:
        return False


def _generation_stale(outdir: Path, gen: int | None) -> bool:
    if gen is None:
        return False
    with _lock:
        current = _outdir_gen.get(_key(outdir))
    if current is None:
        return False
    return current != gen


def _join(timeout: float) -> bool:
    """Wait up to timeout seconds. True when /stop lands during the wait."""
    with _lock:
        threads = [t for t in _inflight if t.is_alive()]
    if not threads or timeout <= 0:
        return _control_stopped()
    _say(f"supervisor: waiting up to {int(timeout)}s for {len(threads)} phase note(s)")
    end = time.monotonic() + timeout
    for thread in threads:
        while thread.is_alive():
            if _control_stopped():
                return True
            remaining = end - time.monotonic()
            if remaining <= 0:
                return False
            thread.join(min(0.5, remaining))
    return _control_stopped()


def _any_alive() -> bool:
    with _lock:
        return any(t.is_alive() for t in _inflight)


def _join_timeout() -> float:
    return float(_env_int("RECON_SUPERVISOR_JOIN", 60, 0, 180))


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(lo, min(hi, value))


@contextmanager
def _model_slot():
    _slots.acquire()
    try:
        yield
    finally:
        _slots.release()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = text.replace("\r\n", "\n")
    if not data.endswith("\n"):
        data += "\n"
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(data, encoding="utf-8", newline="\n")
        tmp.replace(path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def _review_path(outdir: Path, phase: str, *, allow_summary: bool = False) -> Path | None:
    name = safe_phase(phase, allow_summary=allow_summary)
    if not name:
        return None
    root = Path(outdir).resolve()
    path = (root / "reviews" / f"{name}.txt").resolve()
    if not _inside(root, path):
        return None
    return path


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def _rel(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return path.name


def _key(outdir: Path) -> str:
    try:
        return str(Path(outdir).resolve())
    except OSError:
        return str(outdir)


def _looks_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(512)
    except OSError:
        return True


def _say(message: str) -> None:
    try:
        import reconkit

        reconkit.info(message)
    except Exception:
        return
