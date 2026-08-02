"""One-shot doc/version string updater for Reconkit v3.0.0 packaging."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent

FILES = [
    "USAGE.md",
    "OPERATIONS.md",
    "WORKFLOW.md",
    "AGENTS.md",
    "ROADMAP.md",
    "skills/README.md",
    "skills/SKILLS_INDEX.md",
    "reconkit.py",
    "recon_shell.py",
    "recon_prove.py",
    "prove/__init__.py",
    "prove/policy.py",
    "prove/http_util.py",
]

REPLS: list[tuple[str, str]] = [
    ("Reconkit (project root)", "the Reconkit project root"),
    ("v2.2 status", "v3.0 status"),
    ("(v2.2 UI)", "(Bridge UI)"),
    ("v2.2 skill suite", "v3.0 skill suite"),
    ("Program profiles & graph (v2.2)", "Program profiles & graph (v3.0)"),
    ("Program profiles & Graph (v2.2)", "Program profiles & Graph (v3.0)"),
    ("Choose program weights (v2.2)", "Choose program weights"),
    ("Full shell hunt (v2.2 features)", "Full shell hunt (v3.0 features)"),
    ("Typography & evidence console (v2.2 UI)", "Typography & evidence console (Bridge UI)"),
    ("Typography & console theme (v2.2 UI)", "Typography & console theme (Bridge UI)"),
    ("for reconkit v2.2.0", "for reconkit v3.0.0"),
    ("Safe validation / prove layer (v2.2.0)", "Safe validation / prove layer (v3.0.0)"),
    ("(v2.2.0) re-checks", "(v3.0.0) re-checks"),
    ("shell (v2.2.0)", "shell (v3.0.0)"),
    ("reconkit-prove/2.2.0", "reconkit-prove/3.0.0"),
    ('"version": "2.2.0"', '"version": "3.0.0"'),
    ('__version__ = "2.2.0"', '__version__ = "3.0.0"'),
    ("#20-program-profiles--graph-v22", "#20-program-profiles--graph-v30"),
    ("v2.1.0 remains stable", "older releases remain available separately"),
    ("graph (v2.2)", "graph (v3.0)"),
    ("(v2.2)", "(v3.0)"),
]

MOJI = [
    ("â€\"", "—"),
    ("â€“", "–"),
    ("â†’", "→"),
    ("â€¦", "…"),
]


def main() -> None:
    for rel in FILES:
        p = ROOT / rel
        if not p.exists():
            print("skip", rel)
            continue
        t = p.read_text(encoding="utf-8", errors="replace")
        orig = t
        for a, b in REPLS:
            t = t.replace(a, b)
        for a, b in MOJI:
            t = t.replace(a, b)
        if t != orig:
            p.write_text(t, encoding="utf-8", newline="\n")
            print("updated", rel)
        else:
            print("unchanged", rel)


if __name__ == "__main__":
    main()
