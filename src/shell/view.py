"""Local scan view. A dark tracking screen for one reconkit run.

The window reads the live scan file and the target output directory.
It does not start a scan and it does not open a network port.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

BG = "#070b0c"
PANEL = "#0c1214"
CYAN = "#7ef0e0"
CYAN_DIM = "#1a4544"
TEXT = "#e7f6f4"
MUTED = "#7f9a98"
AMBER = "#e0a15a"
GREEN = "#8fd9a8"
LINE = "#143834"


def _line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    count = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.strip():
                    count += 1
    except Exception:
        return 0
    return count


def _read_modules(outdir: Path) -> list[str]:
    path = outdir / "run_meta.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    modules = data.get("modules") if isinstance(data, dict) else None
    if not isinstance(modules, list):
        return []
    return [str(item) for item in modules if str(item).strip()]


def load_snapshot(target: str = "", *, live: dict | None = None, outdir: Path | None = None) -> dict:
    """Counts and phase state for the view. Pass `live` and `outdir` in tests."""
    if live is None:
        from live_mission import read_live

        live = read_live()
    chosen = (target or str(live.get("target") or "")).strip()
    live_target = str(live.get("target") or "").strip()
    use_live = not chosen or chosen == live_target
    if outdir is None and chosen:
        try:
            import reconkit as rk

            outdir = rk.output_dir_for(chosen)
        except Exception:
            outdir = None
    modules = list(live.get("modules") or []) if use_live else []
    if not modules and outdir is not None:
        modules = _read_modules(outdir)
    completed = list(live.get("completed") or []) if use_live else []
    current = str(live.get("current_module") or "") if use_live else ""
    status = str(live.get("status") or "idle") if use_live else "idle"
    if not use_live and outdir is not None and (outdir / "run_meta.json").is_file():
        status = "saved"
    started = float(live.get("started_at") or 0) if use_live else 0.0
    elapsed = float(live.get("elapsed_s") or 0) if use_live else 0.0
    if use_live and live.get("active") and started:
        elapsed = max(0.0, time.time() - started)
    counts = {"subdomains": 0, "alive": 0, "urls": 0}
    if outdir is not None:
        counts = {
            "subdomains": _line_count(outdir / "subdomains.txt"),
            "alive": _line_count(outdir / "alive.txt"),
            "urls": _line_count(outdir / "urls.txt"),
        }
    return {
        "target": chosen,
        "status": status,
        "active": bool(live.get("active")) if use_live else False,
        "modules": modules,
        "completed": completed,
        "current": current,
        "index": int(live.get("current_index") or 0) if use_live else 0,
        "total": int(live.get("total") or len(modules) or 0),
        "tool": str(live.get("current_tool") or "") if use_live else "",
        "message": str(live.get("message") or "") if use_live else "showing saved output",
        "elapsed": elapsed,
        "counts": counts,
    }


def _clock(seconds: float) -> str:
    total = max(0, int(seconds))
    return f"{total // 60:02d}:{total % 60:02d}"


def _fonts(root) -> dict[str, tuple]:
    import tkinter.font as tkfont

    families = {name.lower() for name in tkfont.families(root)}
    face = "Bahnschrift" if "bahnschrift" in families else "Segoe UI"
    mono = "Cascadia Mono" if "cascadia mono" in families else "Consolas"
    return {
        "mark": (face, 13, "bold"),
        "title": (face, 28, "bold"),
        "label": (face, 9),
        "body": (mono, 11),
        "count": (mono, 20, "bold"),
        "small": (mono, 10),
    }


class ScanView:
    def __init__(self, target: str = "") -> None:
        import tkinter as tk

        self.tk = tk
        self.want = (target or "").strip()
        self.snap = load_snapshot(self.want)
        self.angle = 0
        self._beat = 0
        self._phase_rows: list = []
        self.root = tk.Tk()
        self.root.title("reconkit")
        self.root.configure(bg=BG)
        self.root.geometry("1180x720")
        self.root.minsize(960, 600)
        self.font = _fonts(self.root)
        self._build()
        self._apply()
        self.root.after(40, self._tick)

    def _build(self) -> None:
        tk = self.tk
        header = tk.Frame(self.root, bg=BG, height=52)
        header.pack(fill="x")
        header.pack_propagate(False)
        self.mark = tk.Label(header, text="RECONKIT", bg=BG, fg=CYAN, font=self.font["mark"])
        self.mark.pack(side="left", padx=22, pady=12)
        self.clock = tk.Label(header, text="", bg=BG, fg=MUTED, font=self.font["small"])
        self.clock.pack(side="right", padx=22)
        self.status = tk.Label(header, text="IDLE", bg=BG, fg=AMBER, font=self.font["mark"])
        self.status.pack(side="right", padx=8)
        tk.Frame(self.root, bg=CYAN_DIM, height=1).pack(fill="x")

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True)
        left = tk.Frame(body, bg=PANEL, width=280)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Label(left, text="PHASES", bg=PANEL, fg=MUTED, font=self.font["label"]).pack(anchor="w", padx=16, pady=(16, 8))
        self.phase_box = tk.Frame(left, bg=PANEL)
        self.phase_box.pack(fill="both", expand=True, padx=8)

        self.canvas = tk.Canvas(body, bg=BG, highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)

        right = tk.Frame(body, bg=PANEL, width=260)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)
        tk.Label(right, text="SURFACE", bg=PANEL, fg=MUTED, font=self.font["label"]).pack(anchor="w", padx=16, pady=(16, 8))
        self.count_labels = {}
        for key, title in (("subdomains", "SUBDOMAINS"), ("alive", "ALIVE HOSTS"), ("urls", "URLS")):
            tk.Label(right, text=title, bg=PANEL, fg=MUTED, font=self.font["label"]).pack(anchor="w", padx=16, pady=(12, 0))
            label = tk.Label(right, text="0", bg=PANEL, fg=TEXT, font=self.font["count"])
            label.pack(anchor="w", padx=16)
            self.count_labels[key] = label
        tk.Label(right, text="TOOL", bg=PANEL, fg=MUTED, font=self.font["label"]).pack(anchor="w", padx=16, pady=(18, 0))
        self.tool = tk.Label(right, text="—", bg=PANEL, fg=CYAN, font=self.font["body"], wraplength=220, justify="left")
        self.tool.pack(anchor="w", padx=16)
        tk.Label(right, text="ELAPSED", bg=PANEL, fg=MUTED, font=self.font["label"]).pack(anchor="w", padx=16, pady=(18, 0))
        self.elapsed = tk.Label(right, text="00:00", bg=PANEL, fg=TEXT, font=self.font["count"])
        self.elapsed.pack(anchor="w", padx=16)

        tk.Frame(self.root, bg=CYAN_DIM, height=1).pack(fill="x")
        footer = tk.Frame(self.root, bg=BG, height=36)
        footer.pack(fill="x")
        footer.pack_propagate(False)
        self.message = tk.Label(footer, text="", bg=BG, fg=MUTED, font=self.font["small"], anchor="w")
        self.message.pack(fill="x", padx=22, pady=8)

    def _status_color(self, status: str) -> str:
        if status == "running":
            return CYAN
        if status in {"complete", "saved"}:
            return GREEN
        if status in {"failed", "stopped"}:
            return AMBER
        return MUTED

    def _rebuild_phases(self) -> None:
        tk = self.tk
        for child in self.phase_box.winfo_children():
            child.destroy()
        self._phase_rows = []
        modules = self.snap["modules"] or ["—"]
        for index, name in enumerate(modules, start=1):
            row = tk.Frame(self.phase_box, bg=PANEL)
            row.pack(fill="x", pady=1)
            mark = tk.Label(row, text="·", bg=PANEL, fg=MUTED, font=self.font["body"], width=2)
            mark.pack(side="left")
            label = tk.Label(
                row,
                text=f"{index:02d}  {name.replace('_', ' ')}",
                bg=PANEL,
                fg=MUTED,
                font=self.font["small"],
                anchor="w",
            )
            label.pack(side="left", fill="x")
            self._phase_rows.append((name, mark, label))

    def _apply(self) -> None:
        snap = self.snap
        shown = snap["target"] or "no target"
        self.root.title(f"reconkit  {shown}")
        status = str(snap["status"] or "idle").upper()
        self.status.configure(text=status, fg=self._status_color(snap["status"]))
        previous = [name for name, _mark, _label in self._phase_rows]
        if previous != (snap["modules"] or ["—"]):
            self._rebuild_phases()
        done = set(snap["completed"])
        current = snap["current"]
        for name, mark, label in self._phase_rows:
            if name == "—":
                continue
            if name == current and snap["active"]:
                mark.configure(text="▸", fg=CYAN)
                label.configure(fg=CYAN)
            elif name in done:
                mark.configure(text="✔", fg=GREEN)
                label.configure(fg=TEXT)
            else:
                mark.configure(text="·", fg=MUTED)
                label.configure(fg=MUTED)
        for key, label in self.count_labels.items():
            label.configure(text=str(snap["counts"].get(key, 0)))
        self.tool.configure(text=snap["tool"] or "—")
        self.elapsed.configure(text=_clock(snap["elapsed"]))
        self.message.configure(text=snap["message"] or "waiting for a scan")

    def _draw(self) -> None:
        canvas = self.canvas
        canvas.delete("all")
        width = max(canvas.winfo_width(), 400)
        height = max(canvas.winfo_height(), 400)
        cx, cy = width // 2, height // 2 - 10
        radius = min(width, height) // 2 - 70
        radius = max(radius, 90)
        canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius, outline=CYAN_DIM, width=1)
        canvas.create_oval(cx - radius + 28, cy - radius + 28, cx + radius - 28, cy + radius - 28, outline=LINE, width=1)
        canvas.create_arc(
            cx - radius, cy - radius, cx + radius, cy + radius,
            start=self.angle, extent=78, style=self.tk.ARC, outline=CYAN, width=2,
        )
        canvas.create_arc(
            cx - radius + 18, cy - radius + 18, cx + radius - 18, cy + radius - 18,
            start=-self.angle * 1.4, extent=46, style=self.tk.ARC, outline=AMBER, width=2,
        )
        arm = 18
        inset = 28
        for x0, y0, x1, y1 in (
            (inset, inset, inset + arm, inset),
            (inset, inset, inset, inset + arm),
            (width - inset, inset, width - inset - arm, inset),
            (width - inset, inset, width - inset, inset + arm),
            (inset, height - inset, inset + arm, height - inset),
            (inset, height - inset, inset, height - inset - arm),
            (width - inset, height - inset, width - inset - arm, height - inset),
            (width - inset, height - inset, width - inset, height - inset - arm),
        ):
            canvas.create_line(x0, y0, x1, y1, fill=CYAN, width=1)
        target = (self.snap["target"] or "AWAITING").upper()
        canvas.create_text(cx, cy - 12, text=target, fill=TEXT, font=self.font["title"])
        phase = (self.snap["current"] or self.snap["status"] or "idle").replace("_", " ")
        canvas.create_text(cx, cy + 24, text=phase, fill=CYAN, font=self.font["label"])
        index = self.snap["index"]
        total = self.snap["total"]
        progress = f"{index}/{total}" if total else ""
        if progress:
            canvas.create_text(cx, cy + radius + 28, text=progress, fill=MUTED, font=self.font["small"])

    def _tick(self) -> None:
        self.angle = (self.angle + 3) % 360
        self._beat += 1
        self.clock.configure(text=time.strftime("%H:%M:%S", time.localtime()))
        if self._beat % 8 == 0:
            self.snap = load_snapshot(self.want)
            self._apply()
        self._draw()
        self.root.after(40, self._tick)

    def run(self) -> None:
        self.root.mainloop()


def open_view(target: str = "") -> None:
    try:
        import tkinter  # noqa: F401
    except Exception as exc:
        raise SystemExit(f"scan view needs tkinter ({exc})") from exc
    ScanView(target).run()
