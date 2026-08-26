"""
Cooperative pause / stop for recon runs (shell /pause /resume /stop).

Stages and host loops call check() which blocks while paused and raises
RunStopped when stop is requested.

In-flight external tools (nuclei, httpx, subfinder, dnsx, …) are tracked as
subprocess.Popen handles. /stop and Ctrl+C terminate those process trees.

Critical: KeyboardInterrupt must KILL children before unregistering — otherwise
orphans keep running and /stop reports "no live tool subprocess registered".
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from typing import Optional

# Known recon tool binaries — used as fallback when Popen handles were lost
# (e.g. after Ctrl+C unregistered without kill — fixed, but keep as safety net).
KNOWN_TOOL_NAMES = (
    "dnsx",
    "httpx",
    "nuclei",
    "subfinder",
    "amass",
    "naabu",
    "ffuf",
    "katana",
    "gowitness",
    "findomain",
    "assetfinder",
    "chaos",
    "puredns",
    "massdns",
    "alterx",
    "dnsgen",
    "gotator",
    "waybackurls",
    "gau",
    "gauplus",
    "hakrawler",
    "gospider",
    "arjun",
    "paramspider",
    "unfurl",
    "gf",
    "dalfox",
    "qsreplace",
    "interactsh-client",
    "notify",
)


class RunStopped(Exception):
    """Raised when the operator requests /stop or hard-interrupt."""


class RunControl:
    def __init__(self) -> None:
        self._pause = threading.Event()  # set = running; clear = paused
        self._pause.set()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._label = ""
        self._run_id = 0
        # Active child processes started by reconkit.run / pipeline
        self._procs: list[subprocess.Popen] = []
        # PIDs we have ever registered this run (fallback kill list)
        self._pids: set[int] = set()

    def reset(self, label: str = "") -> None:
        """Start of a new run — clear stop/pause and drop stale children."""
        with self._lock:
            self._stop.clear()
            self._pause.set()
            self._label = label
            self._run_id += 1
            self._procs = [p for p in self._procs if p.poll() is None]
            self._pids = {p.pid for p in self._procs if p.pid}

    def pause(self) -> None:
        self._pause.clear()

    def resume(self) -> None:
        self._pause.set()

    def stop(self) -> int:
        """
        Request stop and kill in-flight tool processes.
        Returns number of process groups / orphans signaled.
        """
        self._stop.set()
        self._pause.set()  # unblock waiters so they can see stop
        n = self.kill_children()
        # Always try name-based cleanup — covers orphans from prior Ctrl+C
        n += self.kill_known_tools()
        try:
            from live_mission import mark_stopped
            mark_stopped("stopped by operator (/stop)")
        except Exception:
            pass
        return n

    def hard_interrupt(self) -> int:
        """Ctrl+C path: same as stop (set flag + kill everything)."""
        return self.stop()

    def is_paused(self) -> bool:
        return not self._pause.is_set() and not self._stop.is_set()

    def is_stopped(self) -> bool:
        return self._stop.is_set()

    def status(self) -> str:
        if self._stop.is_set():
            return "stopped"
        if not self._pause.is_set():
            return "paused"
        return "running"

    def label(self) -> str:
        return self._label

    def run_id(self) -> int:
        return self._run_id

    def registered_count(self) -> int:
        return len(self.active_children())

    # ------------------------------------------------------------------ #
    # Child process registry (for hard-stop of nuclei/httpx/…)
    # ------------------------------------------------------------------ #

    def register(self, proc: subprocess.Popen) -> None:
        with self._lock:
            self._procs.append(proc)
            if proc.pid:
                self._pids.add(int(proc.pid))
            # prune finished
            self._procs = [p for p in self._procs if p.poll() is None or p is proc]

    def unregister(self, proc: subprocess.Popen, *, kill_if_alive: bool = False) -> None:
        """Remove from registry. If kill_if_alive and still running, terminate it."""
        if kill_if_alive and proc.poll() is None:
            self._kill_one(proc, force=True)
            try:
                proc.wait(timeout=1.5)
            except Exception:
                pass
        with self._lock:
            self._procs = [p for p in self._procs if p is not proc]

    def active_children(self) -> list[subprocess.Popen]:
        with self._lock:
            live = [p for p in self._procs if p.poll() is None]
            self._procs = list(live)
            return list(live)

    def kill_children(self) -> int:
        """SIGTERM/SIGKILL all registered children (and process group on Unix)."""
        procs = self.active_children()
        n = 0
        for proc in procs:
            if self._kill_one(proc):
                n += 1
        # Also kill by remembered PIDs (handles detached edge cases)
        with self._lock:
            pids = set(self._pids)
        for pid in pids:
            if self._kill_pid(pid, force=False):
                n += 1
        # Brief grace, then SIGKILL leftovers
        if procs or pids:
            time.sleep(0.35)
            for proc in procs:
                if proc.poll() is None:
                    self._kill_one(proc, force=True)
            for pid in pids:
                self._kill_pid(pid, force=True)
        with self._lock:
            self._procs = [p for p in self._procs if p.poll() is None]
            # keep only still-live pids
            self._pids = {p.pid for p in self._procs if p.pid}
        return n

    def kill_known_tools(self) -> int:
        """
        Fallback: kill processes whose command name matches known recon tools.

        Used when Popen handles were lost (historical Ctrl+C bug) or tools
        re-parented. Scoped to the current user when possible.
        """
        n = 0
        if os.name == "nt":
            for name in KNOWN_TOOL_NAMES:
                try:
                    # taskkill by image name
                    r = subprocess.run(
                        ["taskkill", "/F", "/IM", f"{name}.exe", "/T"],
                        capture_output=True,
                        timeout=5,
                    )
                    if r.returncode == 0:
                        n += 1
                except Exception:
                    pass
            return n

        # Unix: pkill -x exact name, then pkill -f as secondary
        for name in KNOWN_TOOL_NAMES:
            try:
                r = subprocess.run(
                    ["pkill", "-TERM", "-x", name],
                    capture_output=True,
                    timeout=3,
                )
                if r.returncode == 0:
                    n += 1
            except Exception:
                pass
        time.sleep(0.25)
        for name in KNOWN_TOOL_NAMES:
            try:
                subprocess.run(
                    ["pkill", "-KILL", "-x", name],
                    capture_output=True,
                    timeout=3,
                )
            except Exception:
                pass
        return n

    @staticmethod
    def _kill_pid(pid: int, *, force: bool = False) -> bool:
        if not pid or pid <= 0:
            return False
        try:
            if os.name == "nt":
                flag = "/F" if force else ""
                cmd = ["taskkill", "/PID", str(pid), "/T"]
                if force:
                    cmd.insert(1, "/F")
                subprocess.run(cmd, capture_output=True, timeout=5)
                return True
            # Prefer process group when pid is session leader
            try:
                pgid = os.getpgid(pid)
                sig = signal.SIGKILL if force else signal.SIGTERM
                os.killpg(pgid, sig)
                return True
            except (ProcessLookupError, PermissionError, OSError):
                sig = signal.SIGKILL if force else signal.SIGTERM
                os.kill(pid, sig)
                return True
        except Exception:
            return False

    @staticmethod
    def _kill_one(proc: subprocess.Popen, *, force: bool = False) -> bool:
        if proc.poll() is not None:
            return False
        try:
            if os.name == "nt":
                # Kill tree via taskkill when possible
                try:
                    cmd = ["taskkill", "/PID", str(proc.pid), "/T"]
                    if force:
                        cmd.insert(1, "/F")
                    subprocess.run(cmd, capture_output=True, timeout=5)
                    return True
                except Exception:
                    if force:
                        proc.kill()
                    else:
                        proc.terminate()
                    return True
            # Unix: start_new_session=True → kill the whole process group
            try:
                pgid = os.getpgid(proc.pid)
                sig = signal.SIGKILL if force else signal.SIGTERM
                os.killpg(pgid, sig)
            except (ProcessLookupError, PermissionError, OSError):
                if force:
                    proc.kill()
                else:
                    proc.terminate()
            return True
        except Exception:
            try:
                proc.kill()
                return True
            except Exception:
                return False

    def check(self) -> None:
        """Block while paused; raise RunStopped if stop requested."""
        if self._stop.is_set():
            self.kill_children()
            raise RunStopped("run stopped by operator (/stop)")
        while not self._pause.is_set():
            if self._stop.is_set():
                self.kill_children()
                raise RunStopped("run stopped by operator (/stop)")
            self._pause.wait(timeout=0.2)
        if self._stop.is_set():
            self.kill_children()
            raise RunStopped("run stopped by operator (/stop)")


# Process-wide control (shell + reconkit share this)
CONTROL = RunControl()


def run_interruptible(
    cmd: list,
    *,
    env: dict | None = None,
    capture: bool = False,
    input_data: bytes | None = None,
    check: bool = False,
    poll: float = 0.25,
    timeout: float | None = None,
) -> subprocess.CompletedProcess:
    """
    Run a tool with pause/stop awareness. /stop and Ctrl+C kill the process group.

    When capturing, stdout/stderr are drained in background threads so a
    chatty tool (nuclei) cannot fill the pipe and deadlock.
    """
    env = env or os.environ.copy()
    do_capture = capture or input_data is not None
    kwargs: dict = {"env": env}
    if do_capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    if input_data is not None:
        kwargs["stdin"] = subprocess.PIPE

    # New session/process group so killpg terminates tool children (nuclei workers)
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **kwargs)
    CONTROL.register(proc)
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    pumps: list[threading.Thread] = []
    aborted = False
    timed_out = False
    last_beat = time.time()
    t0 = time.time()

    def _heartbeat() -> None:
        nonlocal last_beat
        now = time.time()
        if now - last_beat < 10:
            return
        last_beat = now
        try:
            from live_mission import publish
            # Touch updated_at so the dashboard does not mark the run stale
            publish({"active": True, "status": "running"})
        except Exception:
            pass

    def _pump(stream, sink: list[bytes]) -> None:
        if stream is None:
            return
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                sink.append(chunk)
        except Exception:
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    try:
        if do_capture:
            if proc.stdout is not None:
                t = threading.Thread(target=_pump, args=(proc.stdout, stdout_chunks), daemon=True)
                t.start()
                pumps.append(t)
            if proc.stderr is not None:
                t = threading.Thread(target=_pump, args=(proc.stderr, stderr_chunks), daemon=True)
                t.start()
                pumps.append(t)

        if input_data is not None and proc.stdin is not None:
            try:
                proc.stdin.write(input_data)
            except Exception:
                pass
            try:
                proc.stdin.close()
            except Exception:
                pass

        while proc.poll() is None:
            if timeout is not None and (time.time() - t0) >= float(timeout):
                timed_out = True
                CONTROL._kill_one(proc, force=True)
                try:
                    proc.wait(timeout=2)
                except Exception:
                    CONTROL._kill_one(proc, force=True)
                break
            if CONTROL.is_stopped():
                aborted = True
                CONTROL._kill_one(proc)
                try:
                    proc.wait(timeout=2)
                except Exception:
                    CONTROL._kill_one(proc, force=True)
                raise RunStopped("run stopped by operator (/stop)")
            try:
                CONTROL.check()  # also handles pause
            except RunStopped:
                aborted = True
                CONTROL._kill_one(proc)
                try:
                    proc.wait(timeout=2)
                except Exception:
                    CONTROL._kill_one(proc, force=True)
                raise
            _heartbeat()
            time.sleep(poll)

        for t in pumps:
            t.join(timeout=5)
        # If stop killed the process, poll() became non-None without raising — still abort
        if CONTROL.is_stopped():
            aborted = True
            raise RunStopped("run stopped by operator (/stop)")
        stdout = b"".join(stdout_chunks)
        stderr = b"".join(stderr_chunks)
        if timed_out:
            rc = 124
        else:
            rc = proc.returncode if proc.returncode is not None else -1
        result = subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr=stderr)
        if check and rc != 0:
            raise subprocess.CalledProcessError(rc, cmd, output=result.stdout, stderr=result.stderr)
        return result
    except KeyboardInterrupt:
        # Ctrl+C: MUST kill tool before leaving — otherwise orphan dnsx/httpx
        aborted = True
        CONTROL._stop.set()
        CONTROL._kill_one(proc, force=True)
        try:
            proc.wait(timeout=2)
        except Exception:
            CONTROL._kill_one(proc, force=True)
        CONTROL.kill_children()
        CONTROL.kill_known_tools()
        raise RunStopped("run interrupted by Ctrl+C") from None
    finally:
        # If still alive for any reason, force-kill before unregister
        if proc.poll() is None:
            CONTROL._kill_one(proc, force=True)
            try:
                proc.wait(timeout=1)
            except Exception:
                pass
        CONTROL.unregister(proc, kill_if_alive=True)
