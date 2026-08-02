"""
Live slash autocomplete (Grok CLI–style).

While typing:
  /        → all commands listed above the prompt
  /co      → filters to /commands, /config
  /scope   → then space → add, list, check
  /run T --modules  → subdomains, dns, httpprobe, … (not re-listing flags)

UI strategy (Windows-reliable):
  1) Dynamic multi-line prompt: match list is drawn ABOVE the input line
     on every keystroke (does not depend on the floating completion popup).
  2) prompt_toolkit Completer for Tab / ↑↓ / Enter apply.
  3) Bottom toolbar as a second always-on strip.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any, Callable

from shell.suggestions import contextual_suggestions

_LAST_PT_ERROR = ""
_SESSION_OK = False
_ACTIVE_SESSION = None  # PromptSession while shell is alive
_PRINT_LOCK = threading.RLock()


def suggestions_for(text: str) -> list[tuple[str, str]]:
    """Public: (insert, meta) pairs for current buffer text."""
    try:
        return contextual_suggestions(text)
    except Exception:
        return []


# Back-compat alias used by older call sites / tests
_suggestions_for = suggestions_for


def _buffer_text() -> str:
    try:
        from prompt_toolkit.application.current import get_app

        return get_app().current_buffer.document.text_before_cursor or ""
    except Exception:
        return ""


def _suggestion_fragments(text: str) -> list[tuple[str, str]]:
    """FormattedText fragments for the live match strip (above prompt)."""
    if not text.startswith("/"):
        return []

    sugg = suggestions_for(text)
    parts: list[tuple[str, str]] = []

    if not sugg:
        # After free-text (target) show a light hint instead of "no match"
        body = text[1:]
        parts_sp = body.split()
        if len(parts_sp) >= 2 and not text.endswith(" "):
            # mid-word free text — stay quiet
            return []
        if len(parts_sp) >= 2 and text.endswith(" "):
            parts.append(("class:dim", "  "))
            parts.append(("class:dim", "type -- for flags · Tab complete · Enter run"))
            parts.append(("", "\n"))
            return parts
        parts.append(("class:dim", "  no match for "))
        parts.append(("class:tgt-off", text))
        parts.append(("class:dim", "  · try /help or /commands"))
        parts.append(("", "\n"))
        return parts

    # Detect module/value lists — show more columns
    looks_like_modules = any(
        n in {
            "subdomains", "dns", "httpprobe", "tls", "crawl", "js",
            "params", "content", "xss", "sqli", "ssrf_ssti", "nuclei",
            "cloud", "screenshots", "all",
        } or n.startswith("subdomains,") or "," in n
        for n, _ in sugg[:5]
    )
    limit = 20 if looks_like_modules else 14

    parts.append(("class:dim", "  "))
    for i, (name, _meta) in enumerate(sugg[:limit]):
        if i:
            parts.append(("class:dim", "  "))
        style = "class:match-first" if i == 0 else "class:match"
        # Keep strip readable for long csv inserts
        display = name if len(name) <= 28 else name[:25] + "…"
        parts.append((style, display))
    if len(sugg) > limit:
        parts.append(("class:dim", f"  +{len(sugg) - limit} more"))
    parts.append(("", "\n"))

    # Second hint line: description of best match + keys
    best_meta = (sugg[0][1] or "").strip()
    parts.append(("class:dim", "  "))
    if best_meta:
        parts.append(("class:meta", best_meta[:72]))
        parts.append(("class:dim", "  · "))
    parts.append(("class:dim", "Tab complete · Enter run · type more to filter"))
    parts.append(("", "\n"))
    return parts


def make_prompt_toolkit_session():
    """Return PromptSession with live filtering drawn above the prompt."""
    global _LAST_PT_ERROR, _SESSION_OK, _ACTIVE_SESSION
    _SESSION_OK = False
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.application.current import get_app
        from prompt_toolkit.completion import Completer, Completion
        from prompt_toolkit.formatted_text import FormattedText
        from prompt_toolkit.history import FileHistory, InMemoryHistory
        from prompt_toolkit.key_binding import KeyBindings, merge_key_bindings
        from prompt_toolkit.key_binding.defaults import load_key_bindings
        from prompt_toolkit.styles import Style
        from prompt_toolkit.enums import EditingMode
    except ImportError:
        _LAST_PT_ERROR = "prompt_toolkit not installed (pip install prompt_toolkit)"
        return None

    class LiveSlashCompleter(Completer):
        def get_completions(self, document, complete_event):  # noqa: ANN001
            text = document.text_before_cursor or ""
            if text.startswith("/") and " " not in text:
                # Replace whole slash-token
                start = -len(text) if text else 0
            elif text.startswith("/") and " " in text:
                token = "" if text.endswith(" ") else text.rsplit(" ", 1)[-1]
                start = -len(token) if token else 0
            else:
                token = text.rsplit(" ", 1)[-1] if text else ""
                start = -len(token) if token else 0

            for insert, meta in suggestions_for(text):
                yield Completion(
                    text=insert,
                    start_position=start,
                    display=insert,
                    display_meta=meta,
                )

    def bottom_toolbar() -> Any:
        text = _buffer_text()
        if not text.startswith("/"):
            return FormattedText([
                ("class:bottom-toolbar", "  STARFLEET BRIDGE  ·  type / for orders  ·  Tab complete  ·  /dashboard for viewscreen  "),
            ])
        sugg = suggestions_for(text)
        if not sugg:
            return FormattedText([
                ("class:bottom-toolbar", "  Tab · Enter  ·  type -- for flags after target  "),
            ])
        names = "  ".join(n for n, _ in sugg[:12])
        extra = f"  +{len(sugg) - 12}" if len(sugg) > 12 else ""
        return FormattedText([
            ("class:bottom-toolbar", f"  {names}{extra}  │ Tab · Enter  "),
        ])

    # Starfleet / LCARS palette (amber + teal bridge)
    style = Style.from_dict({
        "completion-menu": "bg:#0a1220 #e8eef7",
        "completion-menu.completion": "bg:#0a1220 #e8eef7",
        "completion-menu.completion.current": "bg:#134e4a #ecfeff bold",
        "completion-menu.meta.completion": "bg:#0a1220 #8b9bb4",
        "completion-menu.meta.completion.current": "bg:#134e4a #99f6e4",
        "scrollbar.background": "bg:#0d1524",
        "scrollbar.button": "bg:#f5a623",
        "bottom-toolbar": "noreverse bg:#0a1220 #f5a623",
        "rk": "#5eead4 bold",          # BRIDGE cyan
        "at": "#8b9bb4",
        "ver": "#fbbf24",              # LCARS amber version
        "dim": "#64748b",
        "tgt-on": "#34d399 bold",      # green sector
        "tgt-off": "#f5a623 bold",     # amber when no target
        "v": "#c4b5fd",
        "arrow": "#5eead4 bold",
        "match": "#38bdf8",
        "match-first": "#5eead4 bold",
        "meta": "#94a3b8",
    })

    extra = KeyBindings()

    @extra.add("tab")
    def _on_tab(event) -> None:  # noqa: ANN001
        buf = event.app.current_buffer
        if buf.complete_state:
            buf.complete_next()
        else:
            buf.start_completion(select_first=True)

    def _enter_run(event) -> None:  # noqa: ANN001
        buf = event.app.current_buffer
        st = buf.complete_state
        if st is not None:
            comp = st.current_completion
            if comp is None and st.completions:
                comp = st.completions[0]
            if comp is not None:
                buf.apply_completion(comp)
            else:
                buf.cancel_completion()

        text = (buf.text or "").strip()
        # Unique prefix expand: /comm → /commands
        if text.startswith("/") and " " not in text and len(text) > 1:
            matches = [n for n, _ in suggestions_for(text)]
            canon = []
            seen_cmd: set[str] = set()
            from shell.commands import resolve
            for n in matches:
                cmd = resolve(n.lstrip("/"))
                if cmd and cmd.name not in seen_cmd:
                    seen_cmd.add(cmd.name)
                    canon.append(f"/{cmd.name}")
            if len(canon) == 1 and canon[0] != text:
                buf.text = canon[0]
                buf.cursor_position = len(canon[0])
            elif len(matches) == 1 and matches[0] != text:
                buf.text = matches[0]
                buf.cursor_position = len(matches[0])

        buf.validate_and_handle()

    @extra.add("enter", eager=True)
    def _enter(event) -> None:  # noqa: ANN001
        _enter_run(event)

    @extra.add("c-m", eager=True)
    def _enter_cm(event) -> None:  # noqa: ANN001
        _enter_run(event)

    @extra.add("c-space")
    def _force_menu(event) -> None:  # noqa: ANN001
        buf = event.app.current_buffer
        if buf.complete_state:
            buf.cancel_completion()
        buf.start_completion(select_first=False)

    bindings = merge_key_bindings([load_key_bindings(), extra])

    hist_path = Path.home() / ".reconkit" / "shell_history.txt"
    try:
        hist_path.parent.mkdir(parents=True, exist_ok=True)
        history = FileHistory(str(hist_path))
    except Exception:
        history = InMemoryHistory()

    try:
        session = PromptSession(
            completer=LiveSlashCompleter(),
            complete_while_typing=True,
            complete_in_thread=False,
            history=history,
            style=style,
            key_bindings=bindings,
            bottom_toolbar=bottom_toolbar,
            reserve_space_for_menu=10,
            enable_history_search=False,
            mouse_support=False,
            editing_mode=EditingMode.EMACS,
        )
        _SESSION_OK = True
        _LAST_PT_ERROR = ""
        _ACTIVE_SESSION = session
        return session
    except Exception as exc:
        _LAST_PT_ERROR = f"{type(exc).__name__}: {exc}"
        _SESSION_OK = False
        _ACTIVE_SESSION = None
        return None


def autocomplete_status() -> str:
    if _SESSION_OK:
        return "LIVE ✓"
    if _LAST_PT_ERROR:
        return f"OFF ({_LAST_PT_ERROR[:100]})"
    try:
        import prompt_toolkit  # noqa: F401
    except ImportError:
        return "OFF (pip install prompt_toolkit)"
    return "OFF (use Windows Terminal / cmd.exe, then restart shell)"


def make_pt_message(target: str, verbose: int, vlabel: str) -> Callable[[], Any]:
    """
    Dynamic prompt callable.

    prompt_toolkit re-invokes this on every UI invalidate, so the match
    strip above the input updates as the user types — no floating menu required.
    """
    from prompt_toolkit.formatted_text import FormattedText

    def _message() -> FormattedText:
        parts: list[tuple[str, str]] = []
        text = _buffer_text()
        parts.extend(_suggestion_fragments(text))

        tgt = target if target else "none"
        tgt_style = "class:tgt-on" if target else "class:tgt-off"
        parts.extend([
            ("class:rk", "BRIDGE"),
            ("class:at", "@"),
            ("class:ver", "v3.0.0"),
            ("class:dim", " ["),
            (tgt_style, f"sector:{tgt}"),
            ("class:dim", "] ["),
            ("class:v", f"v:{verbose}:{vlabel}"),
            ("class:dim", "] "),
            ("class:arrow", "◈ "),
        ])
        return FormattedText(parts)

    return _message


def redraw_prompt() -> None:
    """Ask prompt_toolkit to repaint after background output."""
    try:
        from prompt_toolkit.application.current import get_app

        app = get_app()
        app.invalidate()
    except Exception:
        pass


def notify_job_finished(job: Any) -> None:
    """
    Called from the job worker thread when a background scan ends.

    Clears any leftover \\r spinner, prints a one-line status, and forces the
    interactive prompt to redraw so the user does not need to press Enter
    (which previously stacked multiple ghost prompts).
    """
    try:
        from progress_ui import _stop_active_hud

        _stop_active_hud(silent=True)
    except Exception:
        pass

    status = getattr(job, "status", "done")
    jid = getattr(job, "id", "?")
    label = getattr(job, "label", "")
    result = getattr(job, "result", "") or ""
    err = getattr(job, "error", "") or ""

    if status == "done":
        mark, word = "OK", "mission complete"
    elif status == "stopped":
        mark, word = "OK", "mission aborted"
    elif status == "failed":
        mark, word = "FAIL", "mission failed"
    else:
        mark, word = "OK", status

    def _emit() -> None:
        with _PRINT_LOCK:
            try:
                sys.stdout.write("\r\033[2K\n")
                print(f"[{mark}] {word}  ·  job {jid}")
                if status == "done" and result:
                    print(f"  → {result}")
                if status == "failed" and err:
                    first = err.strip().splitlines()[0][:120]
                    print(f"  → {first}")
                print("  bridge ready  ·  type / for orders  ·  /dashboard viewscreen")
                sys.stdout.flush()
            except Exception:
                pass
        redraw_prompt()

    # Prefer UI thread if prompt_toolkit app is active
    try:
        from prompt_toolkit.application.current import get_app

        app = get_app()
        loop = getattr(app, "loop", None) or getattr(app, "eventloop", None)
        if loop is not None and hasattr(loop, "call_from_executor"):
            loop.call_from_executor(_emit)
            return
        if loop is not None and hasattr(loop, "call_soon_threadsafe"):
            loop.call_soon_threadsafe(_emit)
            return
    except Exception:
        pass
    _emit()


def read_line(
    prompt_ansi: str,
    *,
    session=None,
    target: str = "",
    verbose: int = 1,
    vlabel: str = "normal",
) -> str:
    global _LAST_PT_ERROR
    if session is not None:
        try:
            from prompt_toolkit.application.current import get_app

            def _pre_run() -> None:
                """Ensure suggestion strip redraws on every keystroke."""
                try:
                    buf = session.default_buffer

                    def _on_change(_sender) -> None:  # noqa: ANN001
                        try:
                            get_app().invalidate()
                        except Exception:
                            pass

                    if not getattr(buf, "_rk_suggest_hook", False):
                        buf.on_text_changed += _on_change
                        setattr(buf, "_rk_suggest_hook", True)
                except Exception:
                    pass

            # patch_stdout: background job prints hide the prompt, write, then
            # restore it — without this, MISSION COMPLETE leaves a blank line
            # and Enter stacks multiple ghost prompts.
            return session.prompt(
                make_pt_message(target, verbose, vlabel),
                pre_run=_pre_run,
                patch_stdout=True,
            )
        except (KeyboardInterrupt, EOFError):
            raise
        except TypeError:
            # Older prompt_toolkit without patch_stdout kwarg
            try:
                from prompt_toolkit.patch_stdout import patch_stdout

                with patch_stdout(raw=True):
                    return session.prompt(
                        make_pt_message(target, verbose, vlabel),
                        pre_run=_pre_run,
                    )
            except Exception as exc:
                _LAST_PT_ERROR = f"prompt failed: {type(exc).__name__}: {exc}"
        except Exception as exc:
            _LAST_PT_ERROR = f"prompt failed: {type(exc).__name__}: {exc}"
    return input(prompt_ansi)
