"""
Background job runner for the interactive shell.

Runs recon pipelines in a daemon thread so the shell stays usable for
/pause /resume /stop while a scan is live.
"""

from __future__ import annotations

import threading
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

# Statuses that mean the operator still cares about this job
_ACTIVE = frozenset({"pending", "running", "paused", "stopping"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Job:
    id: str
    kind: str
    label: str
    status: str = "pending"  # pending|running|paused|stopping|done|failed|stopped
    created_at: str = field(default_factory=_now)
    started_at: str = ""
    finished_at: str = ""
    error: str = ""
    result: str = ""
    thread: threading.Thread | None = field(default=None, repr=False)


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._current_id: str | None = None

    def list_jobs(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def current(self) -> Job | None:
        """Return the active (or stopping) job, if any."""
        with self._lock:
            if self._current_id:
                j = self._jobs.get(self._current_id)
                if j and j.status in _ACTIVE:
                    return j
            for j in sorted(self._jobs.values(), key=lambda x: x.created_at, reverse=True):
                if j.status in _ACTIVE:
                    return j
            return None

    def mark_stopping(self, job_id: str | None = None) -> Job | None:
        """Mark job as stopping (still tracked) until the worker thread exits."""
        with self._lock:
            j = None
            if job_id:
                j = self._jobs.get(job_id)
            elif self._current_id:
                j = self._jobs.get(self._current_id)
            if j is None:
                for cand in sorted(self._jobs.values(), key=lambda x: x.created_at, reverse=True):
                    if cand.status in ("running", "paused", "pending", "stopping"):
                        j = cand
                        break
            if j and j.status in ("running", "paused", "pending", "stopping"):
                j.status = "stopping"
                return j
            return j

    def submit(self, kind: str, label: str, fn: Callable[[], Any]) -> Job:
        jid = uuid.uuid4().hex[:10]
        job = Job(id=jid, kind=kind, label=label, status="pending")
        with self._lock:
            self._jobs[jid] = job
            self._current_id = jid

        def runner() -> None:
            import os

            # Background jobs share the TTY with the interactive prompt.
            # progress_ui must NOT use \\r live bars (they spam new lines).
            prev_bg = os.environ.get("RECONKIT_BG")
            os.environ["RECONKIT_BG"] = "1"
            with self._lock:
                job.status = "running"
                job.started_at = _now()
            try:
                from run_control import CONTROL

                CONTROL.reset(label=label)
                res = fn()
                with self._lock:
                    if CONTROL.is_stopped() or job.status == "stopping":
                        job.status = "stopped"
                        job.result = "stopped by operator"
                    else:
                        job.status = "done"
                        job.result = str(res) if res is not None else "ok"
                    job.finished_at = _now()
            except BaseException as e:
                # Catch RunStopped + KeyboardInterrupt (BaseException)
                with self._lock:
                    name = e.__class__.__name__
                    if name in ("RunStopped", "KeyboardInterrupt") or job.status == "stopping":
                        job.status = "stopped"
                        job.result = "stopped by operator"
                        job.error = str(e)
                    else:
                        job.status = "failed"
                        job.error = f"{e}\n{traceback.format_exc()[-800:]}"
                    job.finished_at = _now()
                if name == "KeyboardInterrupt":
                    try:
                        from run_control import CONTROL
                        CONTROL.hard_interrupt()
                    except Exception:
                        pass
            finally:
                if prev_bg is None:
                    os.environ.pop("RECONKIT_BG", None)
                else:
                    os.environ["RECONKIT_BG"] = prev_bg
                try:
                    from run_control import CONTROL
                    CONTROL.kill_children()
                    CONTROL.kill_known_tools()
                except Exception:
                    pass
                try:
                    from progress_ui import _stop_active_hud
                    _stop_active_hud(silent=True)
                except Exception:
                    pass
                # Restore interactive prompt (avoid blank line until user hits Enter)
                try:
                    from shell.autocomplete import notify_job_finished
                    notify_job_finished(job)
                except Exception:
                    try:
                        print(f"\n[OK] job {job.id} {job.status} — {job.label}")
                    except Exception:
                        pass

        t = threading.Thread(target=runner, name=f"recon-job-{jid}", daemon=True)
        job.thread = t
        t.start()
        return job


JOBS = JobManager()
