"""
Global configuration for recon-agents.

Priority (highest wins):
  1. CLI flags  (--provider, --model, --base-url, …)
  2. Environment variables  (RECON_LLM_*, OLLAMA_*, OPENAI_*, …)
  3. Config file  (--config PATH, or auto-discovered)
  4. Built-in defaults

Config search order (first file that exists is used, unless --config is set):
  1. $RECON_AGENT_CONFIG
  2. ./config/agent_config.json       (cwd)
  3. ./agent_config.json              (cwd, legacy)
  4. <repo>/config/agent_config.json  (project root)
  5. ~/.reconkit/agent_config.json    (user-global)

Layout (project root = directory containing reconkit.py):
  config/agent_config.json
  config/agent_config.vm-example.json
  config/agent.env.example

Typical split setup:
  - Windows host: Ollama + qwen3:8b (listens on 0.0.0.0:11434)
  - Linux/Windows VM: runs recon agents, points base_url at host IP
"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

HOME = Path.home()
RECONKIT_DIR = HOME / ".reconkit"
GLOBAL_CONFIG_PATH = RECONKIT_DIR / "agent_config.json"
# Project root: parent of the agents/ package (contains reconkit.py, config/, …)
REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"
REPO_CONFIG_PATH = CONFIG_DIR / "agent_config.json"
REPO_CONFIG_VM_EXAMPLE = CONFIG_DIR / "agent_config.vm-example.json"
REPO_ENV_EXAMPLE = CONFIG_DIR / "agent.env.example"

DEFAULT_CONFIG: dict[str, Any] = {
    "llm": {
        # Local: ollama
        # Cloud: openai | xai/grok | anthropic/claude | google/gemini/gemma |
        #        openrouter | groq | deepseek | together | mistral | fireworks | custom
        "provider": "ollama",
        "model": "qwen3:8b",
        # Ollama (local/VM→host): http://127.0.0.1:11434 or http://<WINDOWS_IP>:11434
        # Cloud: leave empty to use provider default, or set OpenAI-compatible base
        "base_url": "http://127.0.0.1:11434",
        "api_key": "",
        "temperature": 0.2,
        "timeout": 300,
        # Ollama only: false = native /api/chat; true = /v1/chat/completions
        "use_openai_compat": False,
    },
    "orchestrator": {
        "max_steps": 12,
        "skip_analyst": False,
        "modules": [],
    },
    "network": {
        "notes": (
            "Local: Ollama on Windows host → set base_url to host IP, OLLAMA_HOST=0.0.0.0. "
            "Cloud: config set --provider xai|anthropic|openai|google|openrouter|groq … "
            "and set the matching API key env var. See: python recon_agents.py providers"
        ),
    },
}


@dataclass
class LLMSettings:
    provider: str = "ollama"
    model: str = "qwen3:8b"
    base_url: str = "http://127.0.0.1:11434"
    api_key: str = ""
    temperature: float = 0.2
    timeout: int = 300
    use_openai_compat: bool = False


@dataclass
class OrchestratorSettings:
    max_steps: int = 12
    skip_analyst: bool = False
    modules: list[str] = field(default_factory=list)


@dataclass
class AgentConfig:
    llm: LLMSettings = field(default_factory=LLMSettings)
    orchestrator: OrchestratorSettings = field(default_factory=OrchestratorSettings)
    network_notes: str = ""
    source_path: str = ""  # which file was loaded (if any)

    def to_dict(self) -> dict[str, Any]:
        return {
            "llm": asdict(self.llm),
            "orchestrator": asdict(self.orchestrator),
            "network": {"notes": self.network_notes},
        }


def deep_merge(base: dict, override: dict) -> dict:
    out = deepcopy(base)
    for k, v in (override or {}).items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out


class ConfigLoadError(ValueError):
    """Raised when an explicit config path is empty or not valid JSON."""


def _read_config_text(path: Path) -> str:
    """
    Read config text, tolerant of UTF-8 BOM and UTF-16 (common when a file
    was edited/saved on Windows and then copied to Linux).
    """
    raw = path.read_bytes()
    if not raw or not raw.strip():
        return ""

    # UTF-16 LE/BE BOM
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")

    # UTF-8 BOM
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig")

    # Heuristic: lots of NULs → likely UTF-16 without BOM
    if raw[:64].count(b"\x00") > 8:
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            pass

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def _parse_config_object(text: str, path: Path) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        raise ConfigLoadError(
            f"Config file is empty: {path}\n"
            f"  Fix: copy the template or re-init:\n"
            f"    cp {REPO_CONFIG_PATH} {path}\n"
            f"    # or:  python recon_agents.py config init --force\n"
            f"    # then edit llm.base_url / model as needed"
        )
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        preview = text[:80].replace("\n", "\\n")
        raise ConfigLoadError(
            f"Config file is not valid JSON: {path}\n"
            f"  parse error: {e}\n"
            f"  starts with: {preview!r}\n"
            f"  Fix: restore a valid file, e.g.\n"
            f"    cp {REPO_CONFIG_PATH} {path}\n"
            f"    # or:  python recon_agents.py config init --force"
        ) from e
    if not isinstance(data, dict):
        raise ConfigLoadError(f"Config root must be a JSON object: {path}")
    return data


def config_file_usable(path: Path) -> bool:
    """True if path exists, is a file, and parses as a JSON object."""
    try:
        if not path.is_file():
            return False
        _parse_config_object(_read_config_text(path), path)
        return True
    except Exception:
        return False


def discover_config_path(
    explicit: str | Path | None = None,
    *,
    require_usable: bool = True,
) -> Path | None:
    """
    Find a config file path.

    When require_usable=True (default for auto-discovery), empty or corrupt
    JSON files are skipped so a broken ~/.reconkit or cwd stub does not crash
    check-llm / agent runs. Explicit --config paths are still returned even if
    missing/empty so the caller can raise a clear error.
    """
    if explicit:
        p = Path(explicit).expanduser().resolve()
        return p  # caller validates existence / contents

    env = os.getenv("RECON_AGENT_CONFIG", "").strip()
    cwd = Path.cwd()
    candidates: list[Path] = []
    if env:
        candidates.append(Path(env).expanduser())
    candidates.extend([
        cwd / "config" / "agent_config.json",
        cwd / "agent_config.json",  # legacy flat layout
        REPO_CONFIG_PATH,
        GLOBAL_CONFIG_PATH,
    ])

    seen: set[Path] = set()
    for c in candidates:
        try:
            resolved = c.expanduser().resolve()
        except Exception:
            resolved = c
        if resolved in seen:
            continue
        seen.add(resolved)
        if not resolved.exists() or not resolved.is_file():
            continue
        if require_usable and not config_file_usable(resolved):
            # Leave a breadcrumb so users know why a file was ignored
            try:
                import sys
                size = resolved.stat().st_size
                print(
                    f"[recon-agents] warning: skipping unusable config "
                    f"({size} bytes): {resolved}",
                    file=sys.stderr,
                )
            except Exception:
                pass
            continue
        return resolved
    return None


def load_raw(path: Path) -> dict[str, Any]:
    return _parse_config_object(_read_config_text(path), path)


def _dict_to_config(data: dict[str, Any], source: str = "") -> AgentConfig:
    merged = deep_merge(DEFAULT_CONFIG, data)
    llm_d = merged.get("llm") or {}
    orch_d = merged.get("orchestrator") or {}
    net_d = merged.get("network") or {}

    llm = LLMSettings(
        provider=str(llm_d.get("provider") or "ollama").lower(),
        model=str(llm_d.get("model") or "qwen3:8b"),
        base_url=str(llm_d.get("base_url") or "http://127.0.0.1:11434").rstrip("/"),
        api_key=str(llm_d.get("api_key") or ""),
        temperature=float(llm_d.get("temperature", 0.2)),
        timeout=int(llm_d.get("timeout", 300)),
        use_openai_compat=bool(llm_d.get("use_openai_compat", False)),
    )
    mods = orch_d.get("modules") or []
    if isinstance(mods, str):
        mods = [m.strip() for m in mods.split(",") if m.strip()]
    orch = OrchestratorSettings(
        max_steps=int(orch_d.get("max_steps", 12)),
        skip_analyst=bool(orch_d.get("skip_analyst", False)),
        modules=list(mods),
    )
    return AgentConfig(
        llm=llm,
        orchestrator=orch,
        network_notes=str(net_d.get("notes") or ""),
        source_path=source,
    )


def _env_client_base_url() -> str:
    """
    Resolve a client-facing LLM base URL from the environment.

    Note: on a Windows Ollama *server*, people set OLLAMA_HOST=0.0.0.0 so the
    daemon listens on all interfaces. That value is NOT a client URL — do not
    treat bare bind addresses as agent base_url.
    """
    for key in ("RECON_LLM_BASE_URL", "OPENAI_BASE_URL", "OLLAMA_HOST"):
        raw = (os.getenv(key) or "").strip()
        if not raw:
            continue
        if key == "OLLAMA_HOST" and not raw.lower().startswith(("http://", "https://")):
            # Server bind only (0.0.0.0 / 127.0.0.1 / hostname without scheme)
            # Prefer RECON_LLM_BASE_URL or the JSON config for the agent client.
            if raw in ("0.0.0.0", "::", "[::]"):
                continue
            raw = "http://" + raw
        return raw.rstrip("/")
    return ""


def apply_env(cfg: AgentConfig) -> AgentConfig:
    """Overlay environment variables onto an already-loaded config."""
    llm = cfg.llm
    provider = os.getenv("RECON_LLM_PROVIDER") or llm.provider
    model = (
        os.getenv("RECON_LLM_MODEL")
        or os.getenv("OLLAMA_MODEL")
        or os.getenv("OPENAI_MODEL")
        or os.getenv("ANTHROPIC_MODEL")
        or os.getenv("XAI_MODEL")
        or os.getenv("GOOGLE_MODEL")
        or llm.model
    )
    base_url = _env_client_base_url() or llm.base_url
    api_key = (
        os.getenv("RECON_LLM_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or os.getenv("XAI_API_KEY")
        or os.getenv("GROK_API_KEY")
        or os.getenv("ANTHROPIC_API_KEY")
        or os.getenv("CLAUDE_API_KEY")
        or os.getenv("GOOGLE_API_KEY")
        or os.getenv("GEMINI_API_KEY")
        or os.getenv("GROQ_API_KEY")
        or os.getenv("OPENROUTER_API_KEY")
        or os.getenv("DEEPSEEK_API_KEY")
        or os.getenv("TOGETHER_API_KEY")
        or os.getenv("MISTRAL_API_KEY")
        or os.getenv("FIREWORKS_API_KEY")
        or llm.api_key
    )
    temp_env = os.getenv("RECON_LLM_TEMPERATURE")
    timeout_env = os.getenv("RECON_LLM_TIMEOUT")
    compat_env = os.getenv("RECON_LLM_OPENAI_COMPAT")

    cfg.llm = LLMSettings(
        provider=str(provider).lower(),
        model=str(model),
        base_url=str(base_url).rstrip("/"),
        api_key=str(api_key or ""),
        temperature=float(temp_env) if temp_env is not None else llm.temperature,
        timeout=int(timeout_env) if timeout_env is not None else llm.timeout,
        use_openai_compat=(
            compat_env.strip().lower() in ("1", "true", "yes", "on")
            if compat_env is not None
            else llm.use_openai_compat
        ),
    )

    max_steps_env = os.getenv("RECON_MAX_STEPS")
    if max_steps_env:
        cfg.orchestrator.max_steps = int(max_steps_env)
    return cfg


def apply_cli_overrides(
    cfg: AgentConfig,
    *,
    provider: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    temperature: float | None = None,
    timeout: int | None = None,
    max_steps: int | None = None,
    use_openai_compat: bool | None = None,
) -> AgentConfig:
    """Apply non-empty CLI overrides (empty string / None = leave alone)."""
    llm = cfg.llm
    if provider:
        try:
            from agents.llm import normalize_provider, provider_preset

            old_p = normalize_provider(llm.provider)
            p = normalize_provider(provider)
            llm.provider = p
            preset = provider_preset(p)
            # Switching provider without explicit model/url → apply cloud/local presets
            if p != old_p:
                if not model and preset.get("default_model"):
                    llm.model = preset["default_model"]
                if not base_url and preset.get("base_url"):
                    llm.base_url = preset["base_url"]
            elif not base_url and p != "ollama" and preset.get("base_url"):
                if not llm.base_url or "11434" in (llm.base_url or ""):
                    llm.base_url = preset["base_url"]
        except Exception:
            llm.provider = provider.lower()
    if model:
        llm.model = model
    if base_url:
        llm.base_url = base_url.rstrip("/")
    if api_key:
        llm.api_key = api_key
    if temperature is not None:
        llm.temperature = temperature
    if timeout is not None:
        llm.timeout = timeout
    if use_openai_compat is not None:
        llm.use_openai_compat = use_openai_compat
    cfg.llm = llm
    if max_steps is not None:
        cfg.orchestrator.max_steps = max_steps
    return cfg


def _try_repair_empty_repo_config() -> Path | None:
    """
    If the project config exists but is empty/corrupt, rewrite it from
    DEFAULT_CONFIG so a broken git checkout or failed edit does not brick agents.
    """
    path = REPO_CONFIG_PATH
    try:
        if not path.exists():
            return None
        if config_file_usable(path):
            return path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n", encoding="utf-8")
        import sys
        print(
            f"[recon-agents] repaired empty/invalid project config → {path}",
            file=sys.stderr,
        )
        return path.resolve()
    except Exception:
        return None


def load_config(config_path: str | Path | None = None) -> AgentConfig:
    """
    Load merged config: defaults ← file ← env.
    CLI overrides should be applied by the caller via apply_cli_overrides().

    Auto-discovery skips empty/corrupt JSON (with a stderr warning) and falls
    back to built-in defaults so commands like check-llm keep working.
    Explicit --config PATH still hard-fails on missing/invalid files.
    """
    explicit = bool(config_path)
    path = discover_config_path(config_path, require_usable=not explicit)

    if explicit:
        p = Path(config_path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
        raw = load_raw(p)
        cfg = _dict_to_config(raw, source=str(p))
        return apply_env(cfg)

    if path and path.exists():
        try:
            raw = load_raw(path)
            cfg = _dict_to_config(raw, source=str(path))
            return apply_env(cfg)
        except ConfigLoadError:
            pass

    # No usable discovered file — repair project template if it is empty
    repaired = _try_repair_empty_repo_config()
    if repaired and config_file_usable(repaired):
        raw = load_raw(repaired)
        cfg = _dict_to_config(raw, source=str(repaired))
        return apply_env(cfg)

    cfg = _dict_to_config({}, source="")
    return apply_env(cfg)


def save_config(cfg: AgentConfig, path: Path | None = None) -> Path:
    path = path or GLOBAL_CONFIG_PATH
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cfg.to_dict(), indent=2) + "\n", encoding="utf-8")
    return path


def init_config(
    path: Path | None = None,
    *,
    base_url: str | None = None,
    model: str | None = None,
    provider: str = "ollama",
    force: bool = False,
) -> Path:
    """Write a starter config for the VM → Windows Ollama layout."""
    path = (path or GLOBAL_CONFIG_PATH).expanduser().resolve()
    if path.exists() and not force:
        raise FileExistsError(
            f"Config already exists: {path}  (pass force=True or --force to overwrite)"
        )

    data = deepcopy(DEFAULT_CONFIG)
    data["llm"]["provider"] = provider
    if model:
        data["llm"]["model"] = model
    if base_url:
        data["llm"]["base_url"] = base_url.rstrip("/")
    data["network"]["notes"] = (
        "Agents (VM) call Ollama on Windows host. "
        "On Windows: setx OLLAMA_HOST 0.0.0.0  then restart the Ollama app/service, "
        "allow TCP 11434 in Windows Firewall, and put the host IP in llm.base_url here."
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def config_summary(cfg: AgentConfig) -> str:
    lines = [
        f"source:     {cfg.source_path or '(defaults + env only — no file loaded)'}",
        f"provider:   {cfg.llm.provider}",
        f"model:      {cfg.llm.model}",
        f"base_url:   {cfg.llm.base_url}",
        f"api_key:    {'(set)' if cfg.llm.api_key else '(empty)'}",
        f"temperature:{cfg.llm.temperature}",
        f"timeout:    {cfg.llm.timeout}s",
        f"openai_compat: {cfg.llm.use_openai_compat}",
        f"max_steps:  {cfg.orchestrator.max_steps}",
        f"modules:    {cfg.orchestrator.modules or '(all)'}",
    ]
    if cfg.network_notes:
        lines.append(f"notes:      {cfg.network_notes[:200]}")
    return "\n".join(lines)
