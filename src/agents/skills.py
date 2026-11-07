"""
Load skill files from skills/ into one model call.

Layout (agentskills.io compatible):
  skills/<skill-name>/SKILL.md
  skills/<skill-name>/references/*.md
  skills/bug-bounty-hunting-prompts/ADAPTATION.md
  skills/bug-bounty-hunting-prompts/phases/<phase>.md

The runtime reads those files. skills/SKILLS_INDEX.md is the human map.
The prompt lists the loaded paths and attaches the bodies. The model does
not get a second copy of the pipeline, and it does not get every vuln pack
on every step.

Env:
  RECON_AGENT_SKILL=reconkit-bug-bounty   # primary (or off)
  RECON_AGENT_SKILL_EXTRA=a,b             # always merge extras
  RECON_AGENT_SKILL_MAX=8000              # total char budget for this call
  RECON_AGENT_SKILL_SURFACE=1             # vuln packs attached per call (0-3)
  RECON_AGENT_HUNT_PHASE=auto             # off | phase file | comma list
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from paths import REPO_ROOT as _ROOT

SKILLS_DIR = _ROOT / "skills"
DEFAULT_SKILL = "reconkit-bug-bounty"

# Role → skill files fetched for that call. One vuln pack may be appended.
ROLE_SKILLS: dict[str, list[str]] = {
    "planner": [
        "reconkit-bug-bounty",
        "reconkit-efficiency",
    ],
    "specialist": [
        "reconkit-bug-bounty",
    ],
    "analyst": [
        "reconkit-fp-eval",
        "reconkit-triage-gate",
        "reconkit-exploit-prove",
    ],
    "critic": [
        "reconkit-fp-eval",
        "reconkit-triage-gate",
    ],
    "prove": [
        "reconkit-fp-eval",
        "reconkit-exploit-prove",
    ],
    "review": [
        "reconkit-fp-eval",
    ],
}

# On-demand mini-skills: keyword/module → skill name (max a few loaded per turn)
SURFACE_SKILLS: list[tuple[str, tuple[str, ...]]] = [
    ("reconkit-vuln-idor", (
        "idor", "bola", "user_id", "userid", "account_id", "order_id",
        "/users/", "/api/v", "object id", "uuid",
    )),
    ("reconkit-vuln-jwt", (
        "jwt", "eyj", "bearer ", "access_token", "id_token", "refresh_token", "alg",
    )),
    ("reconkit-vuln-graphql", (
        "graphql", "__schema", "introspection", "/graphql", "mutation",
    )),
    ("reconkit-vuln-ssrf", (
        "ssrf", "webhook", "callback", "169.254", "metadata", "oast", "collaborator",
    )),
    ("reconkit-vuln-xss", (
        "xss", "dalfox", "kxss", "reflected", "dom xss", "cross-site",
    )),
    ("reconkit-vuln-sqli", (
        "sqli", "sql injection", "sqlmap", "boolean-based", "error-based",
    )),
    ("reconkit-vuln-takeover", (
        "takeover", "cname", "dangling", "nxdomain", "herokuapp", "github.io",
    )),
    ("reconkit-vuln-secrets", (
        "secret", "akia", "aws_key", "api_key", "private key", "webhook",
        "-----begin", "jwt", "token leak",
    )),
]

# Module names that unlock mini-skills without keyword scan
MODULE_SURFACE: dict[str, list[str]] = {
    "xss": ["reconkit-vuln-xss"],
    "sqli": ["reconkit-vuln-sqli"],
    "ssrf_ssti": ["reconkit-vuln-ssrf"],
    "dns": ["reconkit-vuln-takeover"],
    "takeover_plus": ["reconkit-vuln-takeover"],
    "js": ["reconkit-vuln-secrets", "reconkit-vuln-jwt"],
    "jsintel": ["reconkit-vuln-secrets", "reconkit-vuln-jwt"],
    "params": ["reconkit-vuln-idor"],
    "apis": ["reconkit-vuln-idor", "reconkit-vuln-graphql"],
    "graphql": ["reconkit-vuln-graphql"],
    "gitrecon": ["reconkit-vuln-secrets"],
    "cloud": ["reconkit-vuln-secrets", "reconkit-vuln-ssrf"],
    "nuclei": ["reconkit-vuln-takeover", "reconkit-vuln-ssrf"],
    "crawl": ["reconkit-vuln-graphql", "reconkit-vuln-idor"],
}

# One vuln pack per call. Raise with RECON_AGENT_SKILL_SURFACE (max 3).
MAX_SURFACE_SKILLS = 1

# Hunt files kept for this recon project. Bodies are attached in full.
# The char budget above does not cut them, and nothing in them is rewritten.
# phase-00 surface map, phase-04a scope hold, phase-06 triage, phase-09 gate.
HUNT_DIR = SKILLS_DIR / "bug-bounty-hunting-prompts"
HUNT_PHASE_DIR = HUNT_DIR / "phases"
HUNT_SUPPORT = ("ADAPTATION.md",)
BROWSER_MODULES = frozenset({"crawl", "js", "jsintel", "screenshots"})

ROLE_HUNT_PHASES: dict[str, list[str]] = {
    "planner": ["phase-00-recon.md"],
    "analyst": ["phase-06-triage.md"],
    "critic": ["phase-09-triage-gate.md"],
    "review": ["phase-06-triage.md"],
}


def _skill_primary() -> str | None:
    raw = (os.getenv("RECON_AGENT_SKILL") or DEFAULT_SKILL).strip()
    if raw.lower() in ("", "off", "none", "0", "false", "no"):
        return None
    return raw


def _extra_skills() -> list[str]:
    raw = (os.getenv("RECON_AGENT_SKILL_EXTRA") or "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _max_chars() -> int:
    try:
        return max(2000, int(os.getenv("RECON_AGENT_SKILL_MAX", "8000")))
    except ValueError:
        return 8000


def _hunt_override() -> list[str] | None:
    """None means the role map. An empty list means the hunt pack is off."""
    raw = (os.getenv("RECON_AGENT_HUNT_PHASE") or "").strip()
    if not raw or raw.lower() in ("auto", "default"):
        return None
    if raw.lower() in ("off", "none", "0", "false", "no"):
        return []
    names: list[str] = []
    for part in raw.split(","):
        name = part.strip().replace("\\", "/").split("/")[-1]
        if not name:
            continue
        if not name.endswith(".md"):
            name += ".md"
        names.append(name)
    return names


def _hunt_phase_path(name: str) -> Path | None:
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    path = HUNT_PHASE_DIR / name
    if path.is_file():
        return path
    return None


def _hunt_support_path(name: str) -> Path | None:
    path = HUNT_DIR / name
    if path.is_file():
        return path
    return None


def hunt_phase_names(
    role: str,
    *,
    context: str = "",
    modules: list[str] | None = None,
) -> list[str]:
    """Phase filenames for this call. The file body is not modified."""
    override = _hunt_override()
    if override is not None:
        return [n for n in override if _hunt_phase_path(n) is not None]

    mods = {m.lower() for m in (modules or [])}
    if role == "planner":
        names = ["phase-00-recon.md"]
        if mods & BROWSER_MODULES:
            names = ["phase-04a-scope.md", *names]
        return [n for n in names if _hunt_phase_path(n) is not None]

    if role == "review" and mods & BROWSER_MODULES:
        names = ["phase-04a-scope.md", "phase-06-triage.md"]
        return [n for n in names if _hunt_phase_path(n) is not None]

    return [n for n in ROLE_HUNT_PHASES.get(role, []) if _hunt_phase_path(n) is not None]


def hunt_phase_block(
    role: str,
    *,
    context: str = "",
    modules: list[str] | None = None,
) -> str:
    """
    Append the hunt files in full.

    ADAPTATION.md travels with the phase because the phase text points at it.
    The bytes are the file on disk.
    """
    if not HUNT_PHASE_DIR.is_dir():
        return ""
    names = hunt_phase_names(role, context=context, modules=modules)
    if not names and _hunt_override() == []:
        return ""
    if not names:
        return ""

    files: list[tuple[str, Path]] = []
    for support in HUNT_SUPPORT:
        path = _hunt_support_path(support)
        if path is not None:
            files.append((f"skills/bug-bounty-hunting-prompts/{support}", path))
    for name in names:
        path = _hunt_phase_path(name)
        if path is not None:
            files.append((f"skills/bug-bounty-hunting-prompts/phases/{name}", path))
    if not files:
        return ""

    parts = [
        "## hunt phase files",
        "These files were loaded in full from skills/bug-bounty-hunting-prompts.",
        "The text under each path is the file itself.",
        "files:",
        *[f"- {rel}" for rel, _path in files],
    ]
    for rel, path in files:
        body = path.read_text(encoding="utf-8")
        parts.append(f"### {rel}\n{body}")
    return "\n\n".join(parts)


def _surface_limit() -> int:
    try:
        raw = int(os.getenv("RECON_AGENT_SKILL_SURFACE", str(MAX_SURFACE_SKILLS)))
    except ValueError:
        raw = MAX_SURFACE_SKILLS
    return max(0, min(3, raw))


def list_skills() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if not SKILLS_DIR.is_dir():
        return out
    for p in sorted(SKILLS_DIR.iterdir()):
        skill = p / "SKILL.md"
        if p.is_dir() and skill.is_file():
            meta = _parse_frontmatter(skill.read_text(encoding="utf-8", errors="replace"))
            out.append({
                "name": meta.get("name") or p.name,
                "description": (meta.get("description") or "")[:220],
                "path": str(skill),
            })
    return out


def _parse_frontmatter(text: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    if not text.startswith("---"):
        return meta
    end = text.find("\n---", 3)
    if end < 0:
        return meta
    block = text[3:end].strip()
    key = None
    buf: list[str] = []
    for line in block.splitlines():
        if re.match(r"^[a-zA-Z0-9_]+:\s*", line) and not line.startswith(" "):
            if key:
                meta[key] = " ".join(buf).strip().strip("\"'")
            m = re.match(r"^([a-zA-Z0-9_]+):\s*(.*)$", line)
            if not m:
                continue
            key = m.group(1)
            rest = m.group(2).strip()
            if rest in (">", "|"):
                buf = []
            else:
                buf = [rest]
        else:
            if key is not None:
                buf.append(line.strip())
    if key:
        meta[key] = " ".join(buf).strip().strip("\"'")
    return meta


def _body_after_frontmatter(text: str) -> str:
    if not text.startswith("---"):
        return text
    end = text.find("\n---", 3)
    if end < 0:
        return text
    return text[end + 4 :].lstrip("\n")


@lru_cache(maxsize=32)
def load_skill_text(name: str, *, max_chars: int = 8000) -> str:
    path = SKILLS_DIR / name / "SKILL.md"
    if not path.is_file():
        return ""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    body = _body_after_frontmatter(raw).strip()
    if len(body) > max_chars:
        body = body[: max_chars - 30] + "\n\n[skill truncated]\n"
    return body


def load_reference(skill: str, ref_name: str, *, max_chars: int = 4000) -> str:
    path = SKILLS_DIR / skill / "references" / ref_name
    if not path.is_file():
        path = SKILLS_DIR / skill / "references" / f"{ref_name}.md"
    if not path.is_file():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    if len(text) > max_chars:
        text = text[: max_chars - 20] + "\n\n[ref truncated]\n"
    return text.strip()


def detect_surface_skills(
    context: str = "",
    modules: list[str] | None = None,
    *,
    limit: int | None = None,
) -> list[str]:
    """
    Pick on-demand vuln-class skill files from the modules that just ran
    and from keywords in the current context. At most `limit` files.
    """
    if limit is None:
        limit = _surface_limit()
    blob = (context or "").lower()
    mods = [m.lower() for m in (modules or [])]
    hits: list[str] = []
    seen: set[str] = set()

    for m in mods:
        for sk in MODULE_SURFACE.get(m, []):
            if sk not in seen and (SKILLS_DIR / sk / "SKILL.md").is_file():
                seen.add(sk)
                hits.append(sk)

    if blob:
        for sk, kws in SURFACE_SKILLS:
            if sk in seen:
                continue
            if any(k in blob for k in kws):
                if (SKILLS_DIR / sk / "SKILL.md").is_file():
                    seen.add(sk)
                    hits.append(sk)
            if len(hits) >= limit * 2:
                break

    return hits[:limit]


def skills_for_role(
    role: str,
    *,
    context: str = "",
    modules: list[str] | None = None,
) -> list[str]:
    """Ordered unique skill names for a role (+ on-demand surface skills)."""
    primary = _skill_primary()
    if primary is None:
        return []

    base = list(ROLE_SKILLS.get(role, ROLE_SKILLS["planner"]))
    if primary != DEFAULT_SKILL:
        base = [primary] + [s for s in base if s != primary]
    else:
        if DEFAULT_SKILL not in base:
            base.insert(0, DEFAULT_SKILL)

    for extra in _extra_skills():
        if extra not in base:
            base.append(extra)

    # One matching vuln file. The planner only sees modules that already ran.
    if role in ("specialist", "analyst", "critic", "prove", "planner", "review"):
        for sk in detect_surface_skills(context, modules):
            if sk not in base:
                base.append(sk)

    return [s for s in base if (SKILLS_DIR / s / "SKILL.md").is_file()]


def skill_system_block(
    *,
    role: str = "planner",
    include_refs: bool = False,
    max_chars: int | None = None,
    context: str = "",
    modules: list[str] | None = None,
) -> str:
    """
    Attach the skill files this call needs.

    The header tells the model the files were read from skills/. Reference
    notes stay on disk unless include_refs is set. They are searchable via
    /tips and are not pasted into the planner.
    """
    budget = max_chars if max_chars is not None else _max_chars()
    names = skills_for_role(role, context=context, modules=modules)
    parts: list[str] = []
    if names:
        rels = [f"skills/{name}/SKILL.md" for name in names]
        parts = [
            "## skill files",
            "These files were loaded from the skills/ directory for this call.",
            "Follow them. Do not add modules, payloads, or steps they do not allow.",
            "files:",
            *[f"- {rel}" for rel in rels],
        ]

        remaining = budget - sum(len(p) for p in parts) - 80
        per = max(600, remaining // max(len(names), 1))
        for name, rel in zip(names, rels):
            body = load_skill_text(name, max_chars=per)
            if body:
                parts.append(f"### {rel}\n{body}")

        if include_refs:
            ref_budget = min(1200, max(400, budget // 8))
            refs = ("module-pipeline.md",) if role == "planner" else ("triage-signals.md",)
            for ref in refs:
                r = load_reference("reconkit-bug-bounty", ref, max_chars=ref_budget)
                if r:
                    parts.append(f"### skills/reconkit-bug-bounty/references/{ref}\n{r}")

    text = "\n\n".join(parts)
    if text and len(text) > budget:
        text = text[: budget - 24] + "\n\n[skill files truncated]\n"
    hunt = hunt_phase_block(role, context=context, modules=modules)
    if hunt:
        text = f"{text}\n\n{hunt}" if text else hunt
    return text


def _hunt_status() -> dict[str, Any]:
    phases = sorted(p.name for p in HUNT_PHASE_DIR.glob("phase-*.md")) if HUNT_PHASE_DIR.is_dir() else []
    return {
        "dir": str(HUNT_DIR) if HUNT_DIR.is_dir() else None,
        "phases": phases,
        "by_role": {
            "planner_start": hunt_phase_names("planner"),
            "planner_after_modules": hunt_phase_names("planner", modules=["dns"]),
            "planner_browser": hunt_phase_names("planner", modules=["crawl"]),
            "planner_access": hunt_phase_names("planner", context="authenticated session.json"),
            "analyst": hunt_phase_names("analyst"),
            "critic": hunt_phase_names("critic"),
            "review": hunt_phase_names("review"),
            "review_browser": hunt_phase_names("review", modules=["crawl"]),
            "prove": hunt_phase_names("prove"),
            "specialist": hunt_phase_names("specialist"),
        },
    }


def skill_status() -> dict[str, Any]:
    primary = _skill_primary()
    hunt = _hunt_status()
    if primary is None:
        return {
            "enabled": False,
            "name": None,
            "path": None,
            "suite": [],
            "available": list_skills(),
            "hunt": hunt,
        }
    path = SKILLS_DIR / primary / "SKILL.md"
    surface = [
        s["name"] for s in list_skills() if s["name"].startswith("reconkit-vuln-")
    ]
    return {
        "enabled": path.is_file(),
        "name": primary,
        "path": str(path) if path.is_file() else None,
        "suite": {
            "planner": skills_for_role("planner"),
            "specialist": skills_for_role("specialist"),
            "analyst": skills_for_role("analyst"),
            "critic": skills_for_role("critic"),
            "prove": skills_for_role("prove"),
            "review": skills_for_role("review"),
        },
        "surface_skills": surface,
        "available": list_skills(),
        "max_chars": _max_chars(),
        "hunt": hunt,
    }
