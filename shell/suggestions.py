"""
Contextual slash-command suggestions for recon shell.

Fixes cases like:
  /run tesla.com --modules█
    → subdomains  dns  httpprobe  tls  crawl  …  all
  (not re-listing --modules / --bg)

Handles:
  • command names
  • subcommands
  • flags
  • flag *values* (including comma-lists: subdomains,dns,…)
  • subcommand *values* (/keys set <NAME>, /playbook run <name>, …)
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from shell.commands import COMMANDS, resolve

# ---------------------------------------------------------------------------
# Value catalogs (lazy where imports are heavy)
# ---------------------------------------------------------------------------

_FALLBACK_MODULES = [
    "subdomains", "dns", "httpprobe", "tls", "crawl", "js",
    "params", "content", "xss", "sqli", "ssrf_ssti", "nuclei",
    "cloud", "screenshots",
]

_MODULE_META = {
    "subdomains": "enum + passive sources",
    "dns": "dnsx records / CNAME",
    "httpprobe": "httpx live hosts",
    "tls": "tlsx / JARM",
    "crawl": "katana + spiders + gau",
    "js": "JS secrets / endpoints",
    "params": "unfurl + arjun",
    "content": "paths + ffuf",
    "xss": "gf + kxss + dalfox",
    "sqli": "canary SQLi checks",
    "ssrf_ssti": "SSRF / SSTI canaries",
    "nuclei": "template packs",
    "cloud": "S3 / Azure / GCP",
    "screenshots": "gowitness",
    "all": "every module",
}

_VERBOSE_LEVELS = [
    ("0", "quiet"),
    ("1", "normal"),
    ("2", "debug"),
    ("3", "live"),
    ("quiet", "level 0"),
    ("normal", "level 1"),
    ("debug", "level 2"),
    ("live", "level 3"),
]

_RATE_PROFILES = [
    ("show", "print current profile"),
    ("stealth", "lower concurrency"),
    ("normal", "default"),
    ("aggressive", "faster — stay in RoE"),
]

_CONFIG_FLAGS = [
    ("--provider", "ollama | xai | anthropic | openai | …"),
    ("--model", "model id"),
    ("--base-url", "API base URL"),
    ("--api-key", "override key (prefer env)"),
    ("--temperature", "0.0–1.0"),
    ("--timeout", "seconds"),
    ("--max-steps", "planner steps"),
    ("--openai-compat", "true | false"),
    ("--force", "overwrite on init"),
    ("--repo", "write into repo config/"),
    ("--json", "JSON output on show"),
]

_KNOWN_KEYS = [
    "PDCP_API_KEY",
    "GITHUB_TOKEN",
    "SHODAN_API_KEY",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "SECURITYTRAILS_API_KEY",
    "VIRUSTOTAL_API_KEY",
]


def recon_modules(*, include_all: bool = True) -> list[str]:
    try:
        from reconkit import ALL_MODULES
        mods = list(ALL_MODULES)
    except Exception:
        mods = list(_FALLBACK_MODULES)
    if include_all and "all" not in mods:
        mods = mods + ["all"]
    return mods


def module_meta(name: str) -> str:
    if name in _MODULE_META:
        return _MODULE_META[name]
    try:
        from reconkit import MODULE_DESCRIPTIONS
        return (MODULE_DESCRIPTIONS.get(name) or "recon module")[:48]
    except Exception:
        return "recon module"


def prove_techniques() -> list[str]:
    try:
        from prove.validators import list_techniques
        return list(list_techniques())
    except Exception:
        return [
            "xss_reflect", "ssti_math", "nuclei_recheck",
            "takeover_fingerprint", "ssrf_canary_review", "sqli_boolean",
        ]


def playbook_names() -> list[str]:
    try:
        from playbooks import PLAYBOOKS
        return sorted(PLAYBOOKS.keys())
    except Exception:
        return [
            "quick", "full", "js-deep", "vuln-pass", "passive",
            "api-surface", "content-light", "takeover-first",
            "ports-hint", "prove-prep",
        ]


def program_names() -> list[str]:
    names: list[str] = []
    roots = [
        Path(__file__).resolve().parent.parent / "config" / "programs",
        Path.home() / ".reconkit" / "programs",
    ]
    for root in roots:
        if not root.is_dir():
            continue
        for p in sorted(root.glob("*.json")):
            if p.stem not in names:
                names.append(p.stem)
    return names or ["default", "example-web"]


def llm_providers() -> list[str]:
    try:
        from agents.llm import list_providers
        out = []
        for p in list_providers():
            name = p.get("provider") or p.get("name") or ""
            if name and name not in out:
                out.append(name)
        return out or ["ollama", "xai", "anthropic", "openai", "google"]
    except Exception:
        return [
            "ollama", "xai", "anthropic", "openai", "google", "gemma",
            "openrouter", "groq", "deepseek", "together", "mistral",
            "fireworks", "custom",
        ]


def known_api_keys() -> list[str]:
    try:
        from reconkit import KNOWN_API_KEYS
        return list(KNOWN_API_KEYS.keys())
    except Exception:
        return list(_KNOWN_KEYS)


def help_command_names() -> list[str]:
    return [c.name for c in COMMANDS]


# Flags that take a free-form / catalog value (not boolean)
# cmd → { flag: (values_fn | list | None, multi_csv, meta_fn?) }
# values_fn() -> list[str]; None means free text (no value suggestions)


def _catalogs() -> dict[str, dict[str, tuple]]:
    """
    Per-command flag value catalogs.

    Each entry: flag -> (values_callable, is_csv, meta_callable|None)
    Boolean flags are omitted (no value after them).
    """
    mods = lambda: recon_modules(include_all=True)  # noqa: E731
    mmeta = module_meta

    return {
        "run": {
            "--modules": (mods, True, mmeta),
            "-m": (mods, True, mmeta),
        },
        "session": {
            "--cookie": (lambda: [], False, None),
            "--cookie-b": (lambda: [], False, None),
            "--header": (lambda: [], False, None),
            "--header-b": (lambda: [], False, None),
        },
        "agent": {
            "--modules": (mods, True, mmeta),
            "-m": (mods, True, mmeta),
            "--max-steps": (lambda: ["4", "6", "8", "12", "16", "24"], False, None),
        },
        "config": {
            "--provider": (llm_providers, False, lambda n: "LLM provider"),
            "--model": (lambda: [], False, None),  # free text
            "--base-url": (lambda: [
                "http://127.0.0.1:11434",
                "http://192.168.1.4:11434",
                "https://api.x.ai/v1",
                "https://api.anthropic.com",
                "https://api.openai.com/v1",
            ], False, None),
            "--timeout": (lambda: ["60", "120", "180", "300", "600"], False, None),
            "--temperature": (lambda: ["0", "0.2", "0.5", "0.7", "1.0"], False, None),
            "--max-steps": (lambda: ["4", "6", "8", "12", "16"], False, None),
            "--openai-compat": (lambda: ["true", "false"], False, None),
            "--api-key": (lambda: [], False, None),
        },
        "dashboard": {
            "--host": (lambda: ["127.0.0.1", "0.0.0.0"], False, None),
            "--port": (lambda: ["8787", "8080", "9000"], False, None),
        },
        "notable": {
            "--limit": (lambda: ["10", "20", "30", "50", "100"], False, None),
        },
        "findings": {
            "--min-confidence": (lambda: ["C0", "C1", "C2", "C3"], False, lambda n: "min tier"),
            "--confidence": (lambda: ["C0", "C1", "C2", "all"], False, None),
            "--limit": (lambda: ["10", "25", "50", "100"], False, None),
        },
        "eval": {
            "--limit": (lambda: ["10", "15", "20", "30"], False, None),
        },
        "prove": {
            "--technique": (prove_techniques, False, lambda n: "safe validator"),
            "--limit": (lambda: ["5", "10", "20", "50"], False, None),
        },
        "graph": {
            "--min-score": (lambda: ["0", "20", "40", "60", "80"], False, None),
        },
        "report": {},
        "agent-run": {},  # alias handled via resolve
    }


# Subcommand → next-token value catalog (first positional after sub)
# cmd → { sub: (values_fn, meta_fn) }
def _sub_value_catalogs() -> dict[str, dict[str, tuple]]:
    return {
        "keys": {
            "set": (known_api_keys, lambda n: "API key name"),
            "remove": (known_api_keys, lambda n: "API key name"),
        },
        "playbook": {
            "run": (playbook_names, lambda n: "playbook recipe"),
        },
        "program": {
            "set": (program_names, lambda n: "program profile"),
            "show": (program_names, lambda n: "program profile"),
        },
        "verbose": {
            # treat level as "subcommand" values when first arg
            "": (lambda: [v for v, _ in _VERBOSE_LEVELS], None),
        },
        "rate": {
            "": (lambda: [v for v, _ in _RATE_PROFILES], None),
        },
        "help": {
            "": (help_command_names, lambda n: "command help"),
        },
        "prove": {
            # after queue/run/list, optional target (free); after --technique handled as flag
        },
        "config": {
            # set/init → flags, not positional values
        },
    }


# Boolean / switch flags (no value) — still suggested as flags
_BOOL_FLAGS: dict[str, list[str]] = {
    "run": ["--bg", "--background", "--fg", "--foreground"],
    "agent": ["--dry-run", "--approve", "--skip-analyst"],
    "config": ["--force", "--repo", "--json"],
    "dashboard": ["--no-browser", "--bg", "--background"],
    "report": ["--all"],
    "prove": ["--all", "--dry-run"],
    "findings": ["--all"],
    "eval": ["--llm"],
}


def _flag_list(cmd_name: str) -> list[str]:
    cmd = resolve(cmd_name)
    flags: list[str] = []
    seen: set[str] = set()
    catalogs = _catalogs().get(cmd_name, {})
    for f in catalogs:
        if f not in seen:
            seen.add(f)
            flags.append(f)
    for f in _BOOL_FLAGS.get(cmd_name, []):
        if f not in seen:
            seen.add(f)
            flags.append(f)
    if cmd:
        for fl in cmd.flags or []:
            tok = fl.split()[0]
            if tok not in seen:
                seen.add(tok)
                flags.append(tok)
    return flags


def _sub_list(cmd_name: str) -> list[str]:
    cmd = resolve(cmd_name)
    if not cmd:
        return []
    # Prefer real subcommands only (not flags mistakenly listed as subs)
    out: list[str] = []
    for s in cmd.subcommands or []:
        if s.startswith("-"):
            continue
        # "all" on /run is a module value, not a subcommand
        if cmd_name == "run" and s in ("all", "--modules", "--bg", "--fg", "--resume", "--force", "--scope-all"):
            continue
        if s not in out:
            out.append(s)
    # Command-specific canonical subs if map was polluted
    defaults = {
        "scope": ["add", "list", "check"],
        "keys": ["set", "list", "remove"],
        "config": ["show", "path", "init", "set"],
        "findings": ["reindex", "summary"],
        "playbook": ["list", "run"],
        "jobs": ["list", "status"],
        "prove": ["policy", "techniques", "queue", "run", "list", "show"],
        "program": ["list", "show", "set"],
        "graph": ["show", "summary"],
        "verbose": [v for v, _ in _VERBOSE_LEVELS],
        "rate": [v for v, _ in _RATE_PROFILES],
    }
    if not out and cmd_name in defaults:
        out = list(defaults[cmd_name])
    # merge defaults if empty-ish
    if cmd_name in defaults:
        for s in defaults[cmd_name]:
            if s not in out:
                out.append(s)
    return out


def _as_pairs(
    values: list[str],
    *,
    partial: str,
    meta_fn: Callable[[str], str] | None = None,
    default_meta: str = "",
    prefix: str = "",
    exclude: set[str] | None = None,
) -> list[tuple[str, str]]:
    exclude = exclude or set()
    out: list[tuple[str, str]] = []
    for v in values:
        if v in exclude:
            continue
        if partial and not v.lower().startswith(partial.lower()):
            continue
        insert = prefix + v
        meta = meta_fn(v) if meta_fn else default_meta
        out.append((insert, meta or ""))
    return out


def _csv_pairs(
    values: list[str],
    partial: str,
    *,
    meta_fn: Callable[[str], str] | None = None,
    default_meta: str = "module",
) -> list[tuple[str, str]]:
    """
    Complete comma-separated lists.
    partial '' | 'sub' | 'subdomains,' | 'subdomains,dns' | 'subdomains,d'
    """
    if "," in partial:
        head, tail = partial.rsplit(",", 1)
        used = {x.strip() for x in head.split(",") if x.strip()}
        prefix = head + ","
        return _as_pairs(
            values,
            partial=tail.strip(),
            meta_fn=meta_fn,
            default_meta=default_meta,
            prefix=prefix,
            exclude=used,
        )
    used = {partial} if partial in values else set()
    return _as_pairs(
        values,
        partial=partial,
        meta_fn=meta_fn,
        default_meta=default_meta,
        exclude=set(),  # allow typing prefix of first item
    )


def _flag_expects_value(cmd_name: str, flag: str) -> bool:
    if flag in _catalogs().get(cmd_name, {}):
        return True
    # bare flags from help strings like "--modules a,b"
    cmd = resolve(cmd_name)
    if cmd:
        for fl in cmd.flags or []:
            parts = fl.split()
            if parts and parts[0] == flag and len(parts) > 1:
                return True
    return False


def _values_for_flag(cmd_name: str, flag: str) -> tuple[list[str], bool, Callable | None]:
    entry = _catalogs().get(cmd_name, {}).get(flag)
    if entry:
        vals_fn, is_csv, meta_fn = entry
        try:
            vals = list(vals_fn()) if callable(vals_fn) else list(vals_fn or [])
        except Exception:
            vals = []
        return vals, bool(is_csv), meta_fn
    return [], False, None


def contextual_suggestions(text: str) -> list[tuple[str, str]]:
    """
    Return (insert_token, meta) for the *current word* under completion.

    insert_token replaces the current word (or is inserted at cursor if empty).
    """
    if not text:
        return []

    # Bare command names (no leading slash yet)
    if not text.startswith("/"):
        token = text.rsplit(" ", 1)[-1]
        return [
            (c.name, (c.summary or "")[:48])
            for c in COMMANDS
            if not token or c.name.startswith(token)
        ]

    # Command-name only: /ru  /run
    if " " not in text:
        return _match_commands(text)

    body = text[1:]  # without leading /
    ends_space = text.endswith(" ") or body.endswith(" ")
    # split keeping empties only at end via ends_space flag
    parts = body.split()
    if not parts:
        return _match_commands("/")

    cmd_tok = parts[0]
    cmd = resolve(cmd_tok)
    if not cmd:
        # still typing command name with space? unlikely
        return _match_commands("/" + cmd_tok)

    # Tokens after the command name
    after = parts[1:]
    if ends_space:
        partial = ""
        prior = after
    else:
        partial = after[-1] if after else ""
        prior = after[:-1] if after else []

    cmd_name = cmd.name

    # --- --flag=value form ---
    if partial.startswith("-") and "=" in partial:
        flag, val_part = partial.split("=", 1)
        if _flag_expects_value(cmd_name, flag):
            vals, is_csv, meta_fn = _values_for_flag(cmd_name, flag)
            if is_csv:
                pairs = _csv_pairs(vals, val_part, meta_fn=meta_fn)
            else:
                pairs = _as_pairs(vals, partial=val_part, meta_fn=meta_fn)
            # rewrite inserts as flag=value
            return [(f"{flag}={ins}", meta) for ins, meta in pairs]

    # --- value after a flag ---
    if prior:
        prev = prior[-1]
        # Handle --modules= already split? (won't happen with split)
        if prev.startswith("-") and _flag_expects_value(cmd_name, prev):
            vals, is_csv, meta_fn = _values_for_flag(cmd_name, prev)
            if not vals and not is_csv:
                # free-text value — fall through to other flags only if partial starts with -
                if partial.startswith("-") or partial == "":
                    pass  # may still want other suggestions empty
                else:
                    return []  # free text, no catalog
            if is_csv:
                return _csv_pairs(vals, partial, meta_fn=meta_fn, default_meta="module")
            return _as_pairs(vals, partial=partial, meta_fn=meta_fn, default_meta="value")

        # Multi-token: incomplete CSV continues as one token (handled above).
        # Subcommand value position: /keys set <NAME>
        sub = prior[0] if prior else ""
        if sub and not sub.startswith("-"):
            sub_cats = _sub_value_catalogs().get(cmd_name, {})
            if sub in sub_cats and len(prior) == 1:
                vals_fn, meta_fn = sub_cats[sub]
                try:
                    vals = list(vals_fn()) if callable(vals_fn) else list(vals_fn or [])
                except Exception:
                    vals = []
                # if partial looks like a flag, also allow flags
                if partial.startswith("-"):
                    return _flag_suggestions(cmd_name, partial, prior)
                return _as_pairs(
                    vals,
                    partial=partial,
                    meta_fn=meta_fn,
                    default_meta=f"/{cmd_name} {sub}",
                )
            # /playbook run name — done; maybe target free text
            if sub in sub_cats and len(prior) >= 2:
                if partial.startswith("-"):
                    return _flag_suggestions(cmd_name, partial, prior)
                return []

    # --- first token after command: subcommands and/or flags ---
    # Commands with only levels as "subs" (verbose/rate)
    if cmd_name in ("verbose", "rate") and not prior:
        return _as_pairs(
            _sub_list(cmd_name),
            partial=partial,
            default_meta=f"/{cmd_name}",
        )

    if cmd_name == "help" and not prior:
        return _as_pairs(
            help_command_names(),
            partial=partial,
            default_meta="command help",
        )

    # If partial is empty or starts like sub/flag → offer both
    if not prior:
        return _first_arg_suggestions(cmd_name, partial)

    # After target or other free args: offer unused flags
    if partial.startswith("-") or partial == "" or partial.startswith("--"):
        return _flag_suggestions(cmd_name, partial, prior)

    # Free-text middle (target domain) — still offer flags as hints when partial empty
    # but when user types "tesla" don't flood with modules
    if partial and not partial.startswith("-"):
        # Could be first sub still incomplete if prior empty — handled above
        # Could be target: offer nothing (or trailing flags with empty partial only)
        return []

    return _flag_suggestions(cmd_name, partial, prior)


def _first_arg_suggestions(cmd_name: str, partial: str) -> list[tuple[str, str]]:
    """Subcommands + flags for the first argument slot."""
    # Typing a flag → only flags
    if partial.startswith("-"):
        return _flag_suggestions(cmd_name, partial, [])

    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    for s in _sub_list(cmd_name):
        if partial and not s.lower().startswith(partial.lower()):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append((s, f"/{cmd_name} {s}"))

    # Empty partial: also list flags for commands that primarily use flags
    flag_first = {
        "run", "agent", "dashboard", "notable", "report", "graph", "scan",
    }
    if not partial or cmd_name in flag_first:
        # When user is mid-target (partial is domain text), don't spam flags
        if partial and not partial.startswith("-") and cmd_name in flag_first:
            return out  # empty if no subs matched — free target typing
        for p in _flag_suggestions(cmd_name, "", []):
            if p[0] not in seen:
                seen.add(p[0])
                out.append(p)

    if not out and (not partial or partial.startswith("-")):
        return _flag_suggestions(cmd_name, partial, [])

    return out


def _flag_suggestions(
    cmd_name: str,
    partial: str,
    prior: list[str],
) -> list[tuple[str, str]]:
    used = set(prior)
    out: list[tuple[str, str]] = []
    for f in _flag_list(cmd_name):
        if f in used:
            continue
        # skip if already used as --flag=...
        if any(p == f or p.startswith(f + "=") for p in prior):
            continue
        if partial and not f.startswith(partial):
            continue
        expects = _flag_expects_value(cmd_name, f)
        meta = "flag + value" if expects else "flag"
        if f in ("--modules", "-m"):
            meta = "modules: " + ", ".join(recon_modules(include_all=True)[:6]) + "…"
        # Trailing space so Tab on --modules immediately opens the module list
        insert = (f + " ") if expects else f
        out.append((insert, meta))
    return out


def _match_commands(token: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for c in COMMANDS:
        name = f"/{c.name}"
        if token == "/" or name.startswith(token):
            if name not in seen:
                seen.add(name)
                meta = (c.summary or "")[:48]
                subs = _sub_list(c.name)
                if subs:
                    meta = f"{meta}  [{', '.join(subs[:5])}]"
                out.append((name, meta))
        for a in c.aliases:
            an = f"/{a}"
            if (token == "/" or an.startswith(token)) and an not in seen:
                seen.add(an)
                out.append((an, f"alias → /{c.name}"))
    return out


def slash_completions(buffer: str) -> list[str]:
    """String-only completions for readline / palette helpers."""
    return [ins for ins, _ in contextual_suggestions(buffer if buffer else "/")]
