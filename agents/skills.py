"""
Load Agent Skills suite for reconkit multi-agent prompts.

Layout (agentskills.io compatible):
  skills/<skill-name>/SKILL.md
  skills/<skill-name>/references/*.md
  skills/SKILLS_INDEX.md

Default suite routes skills by agent role for max signal / min tokens.

Env:
  RECON_AGENT_SKILL=reconkit-bug-bounty   # primary (or off)
  RECON_AGENT_SKILL_EXTRA=a,b             # always merge extras
  RECON_AGENT_SKILL_MAX=14000             # total char budget for injection
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = _ROOT / "skills"
DEFAULT_SKILL = "reconkit-bug-bounty"

# Role → ordered skills (later skills add FP/PoC depth; budget trimmed)
ROLE_SKILLS: dict[str, list[str]] = {
    "planner": [
        "reconkit-bug-bounty",
        "reconkit-efficiency",
        "reconkit-fp-eval",
    ],
    "specialist": [
        "reconkit-bug-bounty",
        "reconkit-fp-eval",
    ],
    "analyst": [
        "reconkit-bug-bounty",
        "reconkit-fp-eval",
        "reconkit-exploit-prove",
        "reconkit-triage-gate",
    ],
    "critic": [
        "reconkit-fp-eval",
        "reconkit-triage-gate",
        "reconkit-exploit-prove",
    ],
    "prove": [
        "reconkit-fp-eval",
        "reconkit-exploit-prove",
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

# Cap how many mini-skills inject per turn (token budget)
MAX_SURFACE_SKILLS = 3


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
        return max(4000, int(os.getenv("RECON_AGENT_SKILL_MAX", "14000")))
    except ValueError:
        return 14000


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
    limit: int = MAX_SURFACE_SKILLS,
) -> list[str]:
    """
    Pick on-demand vuln-class mini-skills from context text and module names.
    Keeps token cost low: at most `limit` skills.
    """
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

    # Surface mini-skills for roles that act on findings / vulns
    if role in ("specialist", "analyst", "critic", "prove", "planner"):
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
    Build system-prompt appendix: role-routed multi-skill pack + on-demand
    vuln-class mini-skills when context/modules match.
    """
    budget = max_chars if max_chars is not None else _max_chars()
    names = skills_for_role(role, context=context, modules=modules)
    if not names:
        return ""

    core = [n for n in names if not n.startswith("reconkit-vuln-")]
    surface = [n for n in names if n.startswith("reconkit-vuln-")]

    parts: list[str] = [
        "## reconkit agent skill suite",
        f"role={role} core={', '.join(core)}",
        f"surface={', '.join(surface) if surface else '(none — general recon)'}",
        "Follow confidence tiers C0-C4. Prefer kill-fast FP rules. Detection-first.",
    ]

    remaining = budget - sum(len(p) for p in parts) - 100
    # Core first (55%), surface mini-skills share the rest (short slices)
    n_core = max(len(core), 1)
    n_surf = len(surface)
    core_pool = int(remaining * (0.55 if n_surf else 0.85))
    surf_pool = remaining - core_pool if n_surf else 0

    primary_budget = int(core_pool * 0.5) if len(core) > 1 else core_pool
    support_budget = max(700, (core_pool - primary_budget) // max(len(core) - 1, 1))

    for i, name in enumerate(core):
        cap = primary_budget if i == 0 else support_budget
        body = load_skill_text(name, max_chars=cap)
        if body:
            parts.append(f"### skill:{name}\n{body}")

    if surface and surf_pool > 200:
        per = max(500, surf_pool // max(n_surf, 1))
        parts.append("### on-demand vuln-class skills (matched this turn)")
        for name in surface:
            body = load_skill_text(name, max_chars=per)
            if body:
                parts.append(f"#### skill:{name}\n{body}")

    if include_refs or role in ("planner", "analyst"):
        ref_budget = min(1800, max(400, budget // 8))
        if role == "planner":
            for ref in ("module-pipeline.md", "triage-signals.md"):
                r = load_reference("reconkit-bug-bounty", ref, max_chars=ref_budget)
                if r:
                    parts.append(f"### ref:{ref}\n{r}")
        elif role == "analyst":
            for ref in ("report-template.md", "triage-signals.md"):
                r = load_reference("reconkit-bug-bounty", ref, max_chars=ref_budget)
                if r:
                    parts.append(f"### ref:{ref}\n{r}")

    text = "\n\n".join(parts)
    if len(text) > budget:
        text = text[: budget - 40] + "\n\n[skill suite truncated for context]\n"
    return text


def skill_status() -> dict[str, Any]:
    primary = _skill_primary()
    if primary is None:
        return {
            "enabled": False,
            "name": None,
            "path": None,
            "suite": [],
            "available": list_skills(),
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
        },
        "surface_skills": surface,
        "available": list_skills(),
        "max_chars": _max_chars(),
    }
