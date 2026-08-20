# Agents, prove, programs, graph & skills â€” v3.0.0

**Dashboard** (v3.0.0): scan-phase tracker, findings, proofs, attack-path graph,
and insights. CLI remains the engine; the UI is a local viewer and optional
scan control panel.

## Read these first

| Doc | When |
|-----|------|
| **[OPERATIONS.md](OPERATIONS.md)** | Need **every** command / API with examples |
| **[WORKFLOW.md](WORKFLOW.md)** | Need a full ordered hunt (phases A–O) |
| **[USAGE.md](USAGE.md)** | Architecture, configs, troubleshooting |
| **[skills/README.md](skills/README.md)** | Skill suite design |
| **[skills/SKILLS_INDEX.md](skills/SKILLS_INDEX.md)** | C0–C4 + mini-skill triggers |
| **[HUNTER.md](HUNTER.md)** | Session, HAR, inbox, extra modules |
| **[ROADMAP.md](ROADMAP.md)** | What's done vs planned |

## Quick launch

```bash
cd path/to/Reconkit
pip install prompt_toolkit colorama

python recon_shell.py
# LIVE autocomplete: type /co → /commands /config
# /run T --modules  → module list Â· /keys set  → key names

python reconkit.py --version
python recon_dashboard.py
# Tabs: SCAN | FINDINGS | INBOX | PROOFS | GRAPH | INSIGHTS
# Default bind: 127.0.0.1:8787  (use --host 0.0.0.0 from a VM)
# API: GET /api/scan?target=example.com
# Inbox: GET /api/inbox?target=example.com
```

## Shell map (high level)

```text
/setup /verify /wordlists
/scope add|list|check
/keys set|list|remove
/session show|set|clear
/har import  /inbox  /evidence  /wordlist-target
/target /verbose /rate
/run /quick /full /scan /playbook   # /run is BACKGROUND by default; --fg to block
/pause /resume /stop /jobs
/findings reindex
/program list|show|set
/notable /diff /doctor /tips
/prove policy|techniques|queue|run|list|show
/graph summary|show
/report /critic
/config …  /check-llm  /agent …
/dashboard
```

Every command: `/cmd -h` Â· full catalog: **OPERATIONS.md**.  
Scan progress: one bar per tool finish (`progress_ui.py`); bg jobs use log mode.

## Program profiles

```text
/program list
/program set example-web
/findings reindex
/notable
```

Files: `config/programs/*.json` Â· env: `RECON_PROGRAM=…`

## Prove (safe)

```text
/prove policy
/prove queue example.com
/prove run example.com --dry-run
/prove run example.com
/prove run example.com --technique xss_reflect
/prove run example.com --technique cors_origin
/prove run example.com --technique idor_session_diff   # needs /session cookie-A and cookie-B
```

```bash
python recon_prove.py run --target example.com
# Optional: config/exploit_policy.json → oast_base_url, allow_sqli_boolean
```

Maps to confidence **C2** when confirmed (see skill suite below).

## Graph & dashboard

```text
/graph show example.com
/dashboard
# tabs: Recon | Proofs | Graph | Insights
# typography: Helvetica Neue / Inter UI; JetBrains Mono console
```

```bash
curl -s "http://127.0.0.1:8787/api/graph?target=example.com&min_score=40"
curl -s http://127.0.0.1:8787/api/stats/charts
curl -s "http://127.0.0.1:8787/api/proofs?status=confirmed"
```

## LLM agents (local + cloud)

Unified client: Ollama **or** cloud (Grok, Claude, Gemini/Gemma, OpenAI, OpenRouter, Groq, …).

```bash
# List every provider + default model + key env name
python recon_agents.py providers

# Local Ollama (from a VM: Windows host IP, not Kali IP)
python recon_agents.py config set --provider ollama \
  --base-url http://192.168.1.4:11434 --model qwen3:8b

# Cloud examples (set the matching API key in the environment first)
export XAI_API_KEY=...                    # Grok
python recon_agents.py config set --provider xai --model grok-2-latest

export ANTHROPIC_API_KEY=...              # Claude
python recon_agents.py config set --provider anthropic --model claude-sonnet-4-20250514

export GOOGLE_API_KEY=...                 # Gemini / Gemma
python recon_agents.py config set --provider google --model gemini-2.0-flash
python recon_agents.py config set --provider gemma --model gemma-3-27b-it

export OPENAI_API_KEY=...
python recon_agents.py config set --provider openai --model gpt-4o-mini

export OPENROUTER_API_KEY=...
python recon_agents.py config set --provider openrouter \
  --model anthropic/claude-3.5-sonnet

python recon_agents.py check-llm
python recon_agents.py agents             # specialists + skill suite wiring
python recon_agents.py run --target example.com --dry-run
# one-shot override without rewriting config:
python recon_agents.py run --target example.com --provider xai --model grok-2-latest
```

```text
/config set --provider xai --model grok-2-latest
/config set --provider anthropic --model claude-sonnet-4-20250514
/config set --provider ollama --base-url http://192.168.1.4:11434 --model qwen3:8b
/check-llm
/agents
/agent example.com --max-steps 8
```

**Cloud setup (full walkthrough):** **[config/CLOUD_LLM_SETUP.md](config/CLOUD_LLM_SETUP.md)**  
Drop-in config: `config/agent_config.cloud-example.json`  
All provider `llm` blocks: `config/agent_config.cloud-presets.json`  
Snippets catalog: `config/agent_config.cloud-examples.json` Â· env: `config/agent.env.example`  

PowerShell cloud quickstart (Grok):

```powershell
$env:XAI_API_KEY = "xai-..."
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py check-llm
python recon_agents.py run --target example.com --max-steps 8
```

Or: `copy config\agent_config.cloud-example.json config\agent_config.json` then set the key env.

VM → Windows Ollama: host IP only (not Kali IP). Always use **`--flag`** form for `/config set`.

## Agent skill suite

Inputs reviewed: **Bug-Bounty-Agents**, **bughunter-ai**, **claude-bug-bounty**,
**Claude-BugHunter** (under `git_skills/`, gitignored). Runtime packs live in `skills/`.

### Core (always role-routed)

| Skill | Purpose |
|-------|---------|
| `reconkit-bug-bounty` | Master pipeline + scope rules |
| `reconkit-efficiency` | Local/cloud token budgets (â‰¤3 modules/step) |
| `reconkit-fp-eval` | C0–C4 tiers, kill-fast FPs |
| `reconkit-exploit-prove` | Canary PoCs + `/prove` technique map |
| `reconkit-triage-gate` | Pre-report 7-gate / N/A prevention |

| Role | Skills |
|------|--------|
| planner | bug-bounty + efficiency + fp-eval |
| specialist | bug-bounty + fp-eval |
| analyst | bug-bounty + fp-eval + exploit-prove + triage-gate |
| critic | fp-eval + triage-gate + exploit-prove |

### On-demand mini-skills (max 3 / turn)

| Skill | Example when it loads |
|-------|------------------------|
| `reconkit-vuln-xss` | module `xss` |
| `reconkit-vuln-sqli` | module `sqli` |
| `reconkit-vuln-ssrf` | `ssrf_ssti` / cloud / nuclei |
| `reconkit-vuln-jwt` | `js` + bearer / eyJ |
| `reconkit-vuln-secrets` | `js` / cloud secrets |
| `reconkit-vuln-idor` | `params` / crawl APIs |
| `reconkit-vuln-graphql` | crawl + graphql text |
| `reconkit-vuln-takeover` | `dns` / nuclei takeover |

### Confidence path

```text
C0 noise → drop
C1 scanner → /prove or manual
C2 canary confirmed → PoC draft
C3 impact (human) → triage-gate
C4 report-ready
```

```bash
python recon_agents.py agents    # shows suite by role + surface list
# RECON_AGENT_SKILL=reconkit-bug-bounty   # default
# RECON_AGENT_SKILL=off
# RECON_AGENT_SKILL_EXTRA=reconkit-efficiency
# RECON_AGENT_SKILL_MAX=14000
```

### Worked example

```bash
# Surface XSS → mini-skill reconkit-vuln-xss injects for specialist/analyst
python recon_agents.py run --target example.com --modules xss --max-steps 4
python reconkit.py findings reindex
python recon_prove.py run --target example.com --technique xss_reflect
# confirmed proof â‰ˆ C2; write impact manually for C3; /critic for triage-gate
```

Details: **`skills/README.md`** Â· **`skills/SKILLS_INDEX.md`** Â· **USAGE.md Â§21** Â· **OPERATIONS.md Â§14**.

**Exploit path:** C1 → `/prove` (C2) → PoC draft → human impact (C3) → triage (C4).  
No reverse shells / dumps / spray lists in the default path.

## Safety

Detection + safe validation by default. No sqlmap / shells / dumps.  
Scope gate on recon, prove run, and agents.  
Cloud keys never committed.
