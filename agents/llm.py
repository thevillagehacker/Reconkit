"""
Unified LLM client: local Ollama + cloud providers.

Supported providers (aliases in parentheses):
  ollama                  — local/remote Ollama native /api/chat (or /v1)
  openai                  — OpenAI Chat Completions
  xai | grok              — xAI Grok (OpenAI-compatible)
  anthropic | claude      — Anthropic Messages API
  google | gemini | gemma — Google Gemini OpenAI-compatible endpoint
  openrouter              — OpenRouter (many models behind one key)
  groq                    — Groq
  deepseek                — DeepSeek
  together                — Together AI
  mistral                 — Mistral AI
  firestore | fireworks   — Fireworks AI
  custom                  — any OpenAI-compatible base_url + api_key

Config: agent_config.json → env (RECON_LLM_*, provider keys) → CLI flags.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import AgentConfig, LLMSettings, load_config

# Canonical provider → defaults
PROVIDER_PRESETS: dict[str, dict[str, str]] = {
    "ollama": {
        "base_url": "http://127.0.0.1:11434",
        "default_model": "qwen3:8b",
        "api": "ollama",  # ollama | openai | anthropic
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
        "api": "openai",
        "key_env": "OPENAI_API_KEY",
    },
    "xai": {
        "base_url": "https://api.x.ai/v1",
        "default_model": "grok-2-latest",
        "api": "openai",
        "key_env": "XAI_API_KEY",
    },
    "grok": {  # alias → xai
        "base_url": "https://api.x.ai/v1",
        "default_model": "grok-2-latest",
        "api": "openai",
        "key_env": "XAI_API_KEY",
        "canonical": "xai",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "default_model": "claude-sonnet-4-20250514",
        "api": "anthropic",
        "key_env": "ANTHROPIC_API_KEY",
    },
    "claude": {
        "base_url": "https://api.anthropic.com",
        "default_model": "claude-sonnet-4-20250514",
        "api": "anthropic",
        "key_env": "ANTHROPIC_API_KEY",
        "canonical": "anthropic",
    },
    "google": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "default_model": "gemini-2.0-flash",
        "api": "openai",
        "key_env": "GOOGLE_API_KEY",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "default_model": "gemini-2.0-flash",
        "api": "openai",
        "key_env": "GOOGLE_API_KEY",
        "canonical": "google",
    },
    "gemma": {
        # Gemma via Google AI OpenAI-compatible surface (or set model/base for Groq/OpenRouter)
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "default_model": "gemma-3-27b-it",
        "api": "openai",
        "key_env": "GOOGLE_API_KEY",
        "canonical": "google",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "openai/gpt-4o-mini",
        "api": "openai",
        "key_env": "OPENROUTER_API_KEY",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "api": "openai",
        "key_env": "GROQ_API_KEY",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
        "api": "openai",
        "key_env": "DEEPSEEK_API_KEY",
    },
    "together": {
        "base_url": "https://api.together.xyz/v1",
        "default_model": "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        "api": "openai",
        "key_env": "TOGETHER_API_KEY",
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "default_model": "mistral-small-latest",
        "api": "openai",
        "key_env": "MISTRAL_API_KEY",
    },
    "fireworks": {
        "base_url": "https://api.fireworks.ai/inference/v1",
        "default_model": "accounts/fireworks/models/llama-v3p1-70b-instruct",
        "api": "openai",
        "key_env": "FIREWORKS_API_KEY",
    },
    "custom": {
        "base_url": "",
        "default_model": "",
        "api": "openai",
        "key_env": "RECON_LLM_API_KEY",
    },
}

# Aliases normalize to a key in PROVIDER_PRESETS
PROVIDER_ALIASES: dict[str, str] = {
    "x-ai": "xai",
    "x_ai": "xai",
    "chatgpt": "openai",
    "oai": "openai",
    "sonnet": "anthropic",
    "opus": "anthropic",
    "haiku": "anthropic",
    "gemini-pro": "google",
    "google-ai": "google",
    "googleai": "google",
}


def list_providers() -> list[dict[str, str]]:
    """Public catalog for CLI / docs."""
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for name, p in PROVIDER_PRESETS.items():
        canon = p.get("canonical") or name
        if canon in seen and name != canon:
            continue
        if name != canon and p.get("canonical"):
            continue  # skip pure aliases in main list
        seen.add(canon)
        out.append({
            "provider": canon,
            "api": p.get("api", "openai"),
            "base_url": p.get("base_url", ""),
            "default_model": p.get("default_model", ""),
            "key_env": p.get("key_env", "RECON_LLM_API_KEY"),
            "aliases": ",".join(
                a for a, c in PROVIDER_ALIASES.items() if c == canon
            ) + (
                "," + ",".join(
                    a for a, pr in PROVIDER_PRESETS.items()
                    if pr.get("canonical") == canon
                )
            ).rstrip(","),
        })
    # also list common aliases as notes
    return out


def normalize_provider(name: str) -> str:
    n = (name or "ollama").strip().lower()
    if n in PROVIDER_ALIASES:
        n = PROVIDER_ALIASES[n]
    if n in PROVIDER_PRESETS:
        return PROVIDER_PRESETS[n].get("canonical") or n
    return n


def provider_preset(name: str) -> dict[str, str]:
    n = normalize_provider(name)
    # look up by canonical or direct
    if n in PROVIDER_PRESETS:
        p = dict(PROVIDER_PRESETS[n])
        p["name"] = n
        return p
    for k, v in PROVIDER_PRESETS.items():
        if v.get("canonical") == n or k == n:
            p = dict(v)
            p["name"] = n
            return p
    return {
        "name": n,
        "base_url": "",
        "default_model": "",
        "api": "openai",
        "key_env": "RECON_LLM_API_KEY",
    }


@dataclass
class LLMConfig:
    provider: str = "ollama"
    model: str = "qwen3:8b"
    base_url: str = "http://127.0.0.1:11434"
    api_key: str = ""
    temperature: float = 0.2
    timeout: int = 300
    use_openai_compat: bool = False

    def resolve(self) -> "LLMConfig":
        """
        Merge with global config file + env.
        Non-empty fields already set on this instance take priority over the file.
        """
        file_cfg = load_config().llm

        file_provider = normalize_provider(file_cfg.provider or "ollama")
        provider = normalize_provider(self.provider or file_cfg.provider or "ollama")
        preset = provider_preset(provider)

        # Model: explicit self > sensible default when switching off ollama > file > preset
        if self.model:
            model = self.model
        elif provider != "ollama" and file_provider == "ollama":
            model = preset.get("default_model") or file_cfg.model or "qwen3:8b"
        else:
            model = file_cfg.model or preset.get("default_model") or "qwen3:8b"

        if self.base_url:
            base_url = self.base_url.rstrip("/")
        elif provider != "ollama" and file_provider == "ollama":
            base_url = (preset.get("base_url") or file_cfg.base_url or "").rstrip("/")
        else:
            base_url = (file_cfg.base_url or preset.get("base_url") or "").rstrip("/")

        api_key = self.api_key if self.api_key else (file_cfg.api_key or "")
        temperature = self.temperature if self.temperature is not None else file_cfg.temperature
        timeout = self.timeout if self.timeout is not None else file_cfg.timeout
        use_compat = bool(self.use_openai_compat or file_cfg.use_openai_compat)

        # Env key fill if empty
        if not api_key:
            api_key = _env_api_key(provider, preset)

        # Default base_url from preset when empty or still pointing at local ollama for cloud
        base_url = _normalize_base_url(provider, base_url, preset)

        # Cloud providers: openai-compat or anthropic native (not ollama native)
        if provider != "ollama":
            use_compat = True if preset.get("api") == "openai" else use_compat

        return LLMConfig(
            provider=provider,
            model=model,
            base_url=base_url,
            api_key=api_key or "",
            temperature=float(temperature),
            timeout=int(timeout),
            use_openai_compat=bool(use_compat),
        )

    @classmethod
    def from_settings(cls, s: LLMSettings) -> "LLMConfig":
        return cls(
            provider=s.provider,
            model=s.model,
            base_url=s.base_url.rstrip("/"),
            api_key=s.api_key or "",
            temperature=s.temperature,
            timeout=s.timeout,
            use_openai_compat=s.use_openai_compat,
        )

    @classmethod
    def from_agent_config(cls, cfg: AgentConfig) -> "LLMConfig":
        return cls.from_settings(cfg.llm)


def _env_api_key(provider: str, preset: dict[str, str]) -> str:
    # Prefer generic then provider-specific
    for key in (
        "RECON_LLM_API_KEY",
        preset.get("key_env") or "",
        "OPENAI_API_KEY",  # many OpenAI-compat stacks reuse this
    ):
        if not key:
            continue
        val = (os.getenv(key) or "").strip()
        if val:
            return val
    # Extra aliases
    extras = {
        "xai": ("XAI_API_KEY", "GROK_API_KEY"),
        "anthropic": ("ANTHROPIC_API_KEY", "CLAUDE_API_KEY"),
        "google": ("GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_AI_API_KEY"),
        "openrouter": ("OPENROUTER_API_KEY",),
        "groq": ("GROQ_API_KEY",),
        "deepseek": ("DEEPSEEK_API_KEY",),
        "together": ("TOGETHER_API_KEY", "TOGETHERAI_API_KEY"),
        "mistral": ("MISTRAL_API_KEY",),
        "fireworks": ("FIREWORKS_API_KEY", "FIREWORKS_AI_API_KEY"),
        "openai": ("OPENAI_API_KEY",),
    }
    for key in extras.get(provider, ()):
        val = (os.getenv(key) or "").strip()
        if val:
            return val
    return ""


def _normalize_base_url(provider: str, base_url: str, preset: dict[str, str] | None = None) -> str:
    base_url = (base_url or "").rstrip("/")
    preset = preset or provider_preset(provider)
    default = (preset.get("base_url") or "").rstrip("/")

    # If empty, use preset default
    if not base_url:
        if provider == "ollama":
            return "http://127.0.0.1:11434"
        return default or "http://127.0.0.1:11434"

    # Cloud provider still pointing at default ollama port → replace with cloud default
    if provider != "ollama" and default:
        if "11434" in base_url or base_url in (
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:11434",
            "http://localhost:11434",
        ):
            return default

    return base_url


class LLMError(RuntimeError):
    pass


_THINK_RE = re.compile(r"<think>[\s\S]*?</think>", re.IGNORECASE)
_THINK_UNCLOSED_RE = re.compile(r"<think>[\s\S]*$", re.IGNORECASE)


def strip_thinking(text: str) -> str:
    """Strip chain-of-thought wrappers from models that emit them."""
    if not text:
        return text
    text = _THINK_RE.sub("", text)
    text = _THINK_UNCLOSED_RE.sub("", text)
    return text.strip()


class LLMClient:
    def __init__(self, config: LLMConfig | AgentConfig | LLMSettings | None = None):
        if config is None:
            self.config = LLMConfig.from_agent_config(load_config()).resolve()
        elif isinstance(config, AgentConfig):
            self.config = LLMConfig.from_agent_config(config).resolve()
        elif isinstance(config, LLMSettings):
            self.config = LLMConfig.from_settings(config).resolve()
        elif isinstance(config, LLMConfig):
            # resolve to apply presets / env keys
            self.config = config.resolve()
        else:
            raise TypeError(f"Unsupported config type: {type(config)}")

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        json_mode: bool = False,
    ) -> str:
        temp = self.config.temperature if temperature is None else temperature
        provider = self.config.provider
        preset = provider_preset(provider)
        api = preset.get("api", "openai")

        if provider == "ollama" and not self.config.use_openai_compat:
            if not self.config.base_url.rstrip("/").endswith("/v1"):
                text = self._ollama_native(messages, temp, json_mode)
                return strip_thinking(text)

        if api == "anthropic" or provider in ("anthropic", "claude"):
            text = self._anthropic(messages, temp, json_mode)
            return strip_thinking(text)

        text = self._openai_compat(messages, temp, json_mode)
        return strip_thinking(text)

    def _ollama_native(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        json_mode: bool,
    ) -> str:
        url = f"{self.config.base_url.rstrip('/')}/api/chat"
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if json_mode:
            payload["format"] = "json"
        return self._post_json(url, payload, headers={}).get("message", {}).get("content", "")

    def _openai_compat(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        json_mode: bool,
    ) -> str:
        base = self.config.base_url.rstrip("/")
        if self.config.provider == "ollama" and not base.endswith("/v1"):
            base = base + "/v1"
        # Google OpenAI-compat path already includes .../openai
        url = f"{base}/chat/completions"
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature,
        }
        # json_object is not universal — enable for known-good providers
        if json_mode and self.config.provider in (
            "openai", "openrouter", "groq", "xai", "deepseek", "together", "mistral", "fireworks",
        ):
            payload["response_format"] = {"type": "json_object"}

        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        # OpenRouter optional headers (helpful for rankings)
        if self.config.provider == "openrouter":
            headers.setdefault("HTTP-Referer", "https://github.com/thevillagehacker/Bug_Bounty")
            headers.setdefault("X-Title", "reconkit-agents")

        data = self._post_json(url, payload, headers=headers)
        try:
            content = data["choices"][0]["message"]["content"]
            if isinstance(content, list):
                # some providers return content parts
                return "".join(
                    p.get("text", "") if isinstance(p, dict) else str(p) for p in content
                )
            return content or ""
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"Unexpected LLM response shape: {data!r}") from e

    def _anthropic(
        self,
        messages: list[dict[str, str]],
        temperature: float,
        json_mode: bool,
    ) -> str:
        """Anthropic Messages API (not OpenAI-compatible)."""
        base = self.config.base_url.rstrip("/")
        if base.endswith("/v1"):
            url = f"{base}/messages"
        else:
            url = f"{base}/v1/messages"

        system_parts = [m["content"] for m in messages if m.get("role") == "system"]
        chat_msgs = [m for m in messages if m.get("role") in ("user", "assistant")]
        # Anthropic requires alternating roles starting with user
        if not chat_msgs:
            chat_msgs = [{"role": "user", "content": "ping"}]
        if chat_msgs[0].get("role") != "user":
            chat_msgs = [{"role": "user", "content": "(continue)"}] + chat_msgs

        payload: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": 8192,
            "temperature": temperature,
            "messages": [
                {"role": m["role"], "content": m["content"]} for m in chat_msgs
            ],
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        if json_mode:
            # soft hint — Anthropic has no strict json_object for all models
            payload["messages"] = list(payload["messages"])
            last = dict(payload["messages"][-1])
            last["content"] = (
                last.get("content", "")
                + "\n\nRespond with a single JSON object only, no markdown fences."
            )
            payload["messages"][-1] = last

        if not self.config.api_key:
            raise LLMError(
                "Anthropic/Claude requires an API key. Set ANTHROPIC_API_KEY or "
                "llm.api_key / RECON_LLM_API_KEY."
            )

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
        }
        data = self._post_json(url, payload, headers=headers)
        try:
            blocks = data.get("content") or []
            texts = []
            for b in blocks:
                if isinstance(b, dict) and b.get("type") == "text":
                    texts.append(b.get("text") or "")
                elif isinstance(b, dict) and "text" in b:
                    texts.append(str(b.get("text")))
            if texts:
                return "".join(texts)
            # fallback shapes
            if isinstance(data.get("completion"), str):
                return data["completion"]
            raise KeyError("content")
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"Unexpected Anthropic response shape: {data!r}") from e

    def _post_json(self, url: str, payload: dict, headers: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        req_headers = {"Content-Type": "application/json", **headers}
        req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            raise LLMError(
                f"LLM HTTP {e.code} from {url}: {err_body[:800] or e.reason}"
            ) from e
        except urllib.error.URLError as e:
            raise LLMError(self._reachability_hint(url, e.reason)) from e
        except TimeoutError as e:
            raise LLMError(
                f"LLM request timed out after {self.config.timeout}s → {url}. "
                f"Increase llm.timeout in agent_config.json for slow models."
            ) from e
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise LLMError(f"LLM returned non-JSON: {raw[:300]}") from e

    def _reachability_hint(self, url: str, reason: Any) -> str:
        host = self.config.base_url
        provider = self.config.provider
        if provider == "ollama":
            return (
                f"Cannot reach LLM at {url}: {reason}\n"
                f"  Configured base_url: {host}\n"
                f"  model: {self.config.model}  provider: {provider}\n"
                f"\n"
                f"  Split setup checklist (agents in VM, Ollama on Windows):\n"
                f"  1. On Windows: Ollama running; `ollama list` shows {self.config.model}\n"
                f"  2. On Windows: setx OLLAMA_HOST 0.0.0.0 then restart Ollama\n"
                f"  3. Firewall: allow inbound TCP 11434\n"
                f"  4. In VM, base_url = Windows host IP (not 127.0.0.1)\n"
                f"  5. curl http://<WINDOWS_IP>:11434/api/tags\n"
                f"  6. Or switch to cloud: config set --provider xai --model grok-2-latest\n"
            )
        return (
            f"Cannot reach LLM at {url}: {reason}\n"
            f"  provider={provider}  model={self.config.model}\n"
            f"  base_url={host}\n"
            f"  api_key={'set' if self.config.api_key else 'MISSING'}\n"
            f"\n"
            f"  Cloud checklist:\n"
            f"  1. Set API key: RECON_LLM_API_KEY or provider key "
            f"({provider_preset(provider).get('key_env', 'RECON_LLM_API_KEY')})\n"
            f"  2. python recon_agents.py config set --provider {provider} "
            f"--model {self.config.model}\n"
            f"  3. python recon_agents.py check-llm\n"
            f"  4. python recon_agents.py providers   # list presets\n"
        )

    def chat_json(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
    ) -> dict[str, Any]:
        text = self.chat(messages, temperature=temperature, json_mode=True)
        return parse_json_response(text)

    def list_ollama_models(self) -> list[str]:
        """GET /api/tags — Ollama only."""
        url = f"{self.config.base_url.rstrip('/')}/api/tags"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=min(30, self.config.timeout)) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return [m.get("name", "") for m in data.get("models", []) if m.get("name")]
        except Exception as e:
            raise LLMError(f"Could not list Ollama models at {url}: {e}") from e

    def ping(self) -> str:
        """Minimal connectivity check used by check-llm."""
        return self.chat(
            [
                {"role": "system", "content": "Reply with exactly: pong"},
                {"role": "user", "content": "ping"},
            ],
            temperature=0,
        )


def parse_json_response(text: str) -> dict[str, Any]:
    """Best-effort extract of a JSON object from model output."""
    text = strip_thinking((text or "").strip())
    if not text:
        raise LLMError("Empty LLM response when JSON was expected")

    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
        return {"value": data}
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start : end + 1])
                if isinstance(data, dict):
                    return data
            except json.JSONDecodeError:
                pass
        raise LLMError(f"Could not parse JSON from LLM response: {text[:400]}")
