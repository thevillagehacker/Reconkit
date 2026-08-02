# Cloud LLM setup for recon agents

Your active config lives at:

```text
config/agent_config.json
```

By default it points at **local Ollama**. To use **cloud** models (Grok, Claude, OpenAI, Gemini, …), set a provider + API key.

Related files:

| File | Purpose |
|------|---------|
| `agent_config.cloud-example.json` | **Drop-in** full config (Grok example) |
| `agent_config.cloud-presets.json` | All cloud `llm` blocks + PowerShell one-liners |
| `agent_config.cloud-examples.json` | Short catalog of llm snippets |
| `agent.env.example` | Env var checklist |

---

## Fastest path (recommended)

### 1. Get an API key

| Provider | Sign up / key | Env var |
|----------|---------------|---------|
| **xAI Grok** | [console.x.ai](https://console.x.ai/) | `XAI_API_KEY` |
| **Anthropic Claude** | [console.anthropic.com](https://console.anthropic.com/) | `ANTHROPIC_API_KEY` |
| **OpenAI** | [platform.openai.com](https://platform.openai.com/) | `OPENAI_API_KEY` |
| **Google Gemini** | [aistudio.google.com](https://aistudio.google.com/) | `GOOGLE_API_KEY` |
| **OpenRouter** | [openrouter.ai](https://openrouter.ai/) | `OPENROUTER_API_KEY` |
| **Groq** | [console.groq.com](https://console.groq.com/) | `GROQ_API_KEY` |

### 2. Set the key (PowerShell)

**This terminal only:**

```powershell
$env:XAI_API_KEY = "xai-your-real-key"
```

**Permanent (new terminals after reopening):**

```powershell
setx XAI_API_KEY "xai-your-real-key"
# close and reopen the terminal
```

### 3. Point recon at the cloud provider

```powershell
cd C:\Users\navee\GitHub\Bug_Bounty\scripts\v2.2.0

python recon_agents.py providers
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py config show
python recon_agents.py check-llm
```

Expect: `OK — model replied: pong` (or similar).

### 4. Run agents

```powershell
# dry-run plan only
python recon_agents.py run --target example.com --dry-run

# real run (target must be in scope)
python recon_agents.py run --target example.com --max-steps 8
```

From the interactive shell:

```text
/config set --provider xai --model grok-2-latest
/check-llm
/agent example.com --max-steps 8
```

---

## Option B — Copy the example config file

```powershell
cd C:\Users\navee\GitHub\Bug_Bounty\scripts\v2.2.0

copy config\agent_config.cloud-example.json config\agent_config.json
# edit provider/model if you want something other than Grok

$env:XAI_API_KEY = "xai-..."
python recon_agents.py check-llm
```

The example file looks like this (keys stay empty — use env):

```json
{
  "llm": {
    "provider": "xai",
    "model": "grok-2-latest",
    "base_url": "https://api.x.ai/v1",
    "api_key": "",
    "temperature": 0.2,
    "timeout": 120,
    "use_openai_compat": true
  },
  "orchestrator": {
    "max_steps": 12,
    "skip_analyst": false,
    "modules": []
  },
  "network": {
    "notes": "Cloud mode: keys from env..."
  }
}
```

---

## Other providers (copy / paste)

```powershell
# Claude
$env:ANTHROPIC_API_KEY = "sk-ant-..."
python recon_agents.py config set --provider anthropic --model claude-sonnet-4-20250514

# OpenAI
$env:OPENAI_API_KEY = "sk-..."
python recon_agents.py config set --provider openai --model gpt-4o-mini

# Gemini
$env:GOOGLE_API_KEY = "..."
python recon_agents.py config set --provider google --model gemini-2.0-flash

# OpenRouter (many models behind one key)
$env:OPENROUTER_API_KEY = "..."
python recon_agents.py config set --provider openrouter --model anthropic/claude-3.5-sonnet

# Groq (fast open models)
$env:GROQ_API_KEY = "..."
python recon_agents.py config set --provider groq --model llama-3.3-70b-versatile
```

Full `llm` JSON for each provider: **`agent_config.cloud-presets.json`**.

---

## One-shot (no config file rewrite)

```powershell
$env:XAI_API_KEY = "xai-..."
python recon_agents.py run --target example.com --provider xai --model grok-2-latest --max-steps 6
```

---

## Switch back to local Ollama

```powershell
python recon_agents.py config set --provider ollama --base-url http://127.0.0.1:11434 --model qwen3:8b
python recon_agents.py check-llm
```

VM → Windows host Ollama: use the **Windows host IP**, e.g. `http://192.168.1.4:11434`.

---

## Priority (what wins)

```text
CLI flags  >  environment vars  >  config/agent_config.json  >  built-in defaults
```

So:

- `config set` writes the JSON file  
- `$env:XAI_API_KEY` supplies the key at runtime  
- `--provider xai` on a single command overrides the file for that run  

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `api_key: (empty)` and HTTP 401 | Key not in env for this shell — set `$env:...` again |
| Still hitting port `11434` | Provider still `ollama` — run `config set --provider xai` |
| `check-llm` timeout | Raise timeout: `config set --timeout 180` |
| Wrong model name | `python recon_agents.py providers` for defaults |
| Works in CLI, not shell | Shell was started before `setx` — restart shell |

```powershell
python recon_agents.py config show
python recon_agents.py providers
python recon_agents.py check-llm
```

---

## Safety

- Do **not** commit API keys  
- Prefer env vars over putting secrets in `agent_config.json`  
- Cloud agents still respect **scope** (`~/.reconkit/scope.txt`)  
