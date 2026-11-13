# Agents, prove, programs & skills -- v3.0.0

CLI is the engine. Findings and proofs are `recon.py` commands.

## Read these first

| Doc | When |
|-----|------|
| **[USAGE.md](USAGE.md)** | Commands, modules, and one hunt |
| **[HUNTER.md](HUNTER.md)** | Session, HAR, inbox, extra modules |
| **[config/CLOUD_LLM_SETUP.md](config/CLOUD_LLM_SETUP.md)** | Cloud model setup |
| **[skills/README.md](skills/README.md)** | Skill suite design |
| **[skills/SKILLS_INDEX.md](skills/SKILLS_INDEX.md)** | C0-C4 + mini-skill triggers |

## Quick launch

```bash
cd path/to/Reconkit
pip install colorama

python recon.py example.com
python recon.py modules
python recon.py keys set PDCP_API_KEY <token>
python recon.py --version
```

## Command map

```text
python recon.py setup | verify | wordlists
python recon.py scope add|list|check
python recon.py keys set|list|remove
python recon.py session show|set|clear
python recon.py har | inbox | evidence | wordlist-target
python recon.py rate | set
python recon.py <target> [--modules a,b] [--resume] [--review]
python recon.py playbook list|run
python recon.py findings reindex
python recon.py program list|show|set
python recon.py notable | diff | doctor | tips
python recon.py prove policy|techniques|queue|run|list|show
python recon.py report | critic
python recon.py agents ...
```

Every command: `python recon.py help <command>`. Full catalog: **[USAGE.md](USAGE.md)**.  
A scan prints one phase line, one result row per finished tool, and one `[+] SCAN COMPLETE` line. HTTP probe prints one line per host. Warnings print on their own line. Ctrl+C stops the scan.

## Program profiles

```bash
python recon.py program list
python recon.py program set example-web
python recon.py findings reindex
python recon.py notable --target example.com
```

Files: `config/programs/*.json`  /  env: `RECON_PROGRAM=...`

## Prove (safe)

```bash
python recon.py prove policy
python recon.py prove queue --target example.com
python recon.py prove run --target example.com --dry-run
python recon.py prove run --target example.com
python recon.py prove run --target example.com --technique xss_reflect
python recon.py prove run --target example.com --technique cors_origin
python recon.py prove run --target example.com --technique idor_session_diff
```

`idor_session_diff` needs cookie A and cookie B from `python recon.py session set`.

```bash
python recon.py prove run --target example.com
# Optional: config/exploit_policy.json -> oast_base_url, allow_sqli_boolean
```

Maps to confidence **C2** when confirmed (see skill suite below).

## LLM agents (local + cloud)

Unified client: Ollama **or** cloud (Grok, Claude, Gemini/Gemma, OpenAI, OpenRouter, Groq, ...).

```bash
# List every provider + default model + key env name
python recon.py agents providers

# Local Ollama (from a VM: Windows host IP, not Kali IP)
python recon.py agents config set --provider ollama \
  --base-url http://192.168.1.4:11434 --model qwen3:8b

# Cloud examples (set the matching API key in the environment first)
export XAI_API_KEY=...                    # Grok
python recon.py agents config set --provider xai --model grok-2-latest

export ANTHROPIC_API_KEY=...              # Claude
python recon.py agents config set --provider anthropic --model claude-sonnet-4-20250514

export GOOGLE_API_KEY=...                 # Gemini / Gemma
python recon.py agents config set --provider google --model gemini-2.0-flash
python recon.py agents config set --provider gemma --model gemma-3-27b-it

export OPENAI_API_KEY=...
python recon.py agents config set --provider openai --model gpt-4o-mini

export OPENROUTER_API_KEY=...
python recon.py agents config set --provider openrouter \
  --model anthropic/claude-3.5-sonnet

python recon.py agents check-llm
python recon.py agents             # specialists + skill suite wiring
python recon.py agents run --target example.com --dry-run
# one-shot override without rewriting config:
python recon.py agents run --target example.com --provider xai --model grok-2-latest
```

```bash
python recon.py agents config set --provider xai --model grok-2-latest
python recon.py agents config set --provider anthropic --model claude-sonnet-4-20250514
python recon.py agents config set --provider ollama --base-url http://192.168.1.4:11434 --model qwen3:8b
python recon.py agents check-llm
python recon.py agents
python recon.py agents run --target example.com --max-steps 8
```

**Cloud setup (full walkthrough):** **[config/CLOUD_LLM_SETUP.md](config/CLOUD_LLM_SETUP.md)**  
Drop-in config: `config/agent_config.cloud-example.json`  
All provider `llm` blocks: `config/agent_config.cloud-presets.json`  
Snippets catalog: `config/agent_config.cloud-examples.json`  /  env: `config/agent.env.example`  

PowerShell cloud quickstart (Grok):

```powershell
$env:XAI_API_KEY = "xai-..."
python recon.py agents config set --provider xai --model grok-2-latest
python recon.py agents check-llm
python recon.py agents run --target example.com --max-steps 8
```

Or: `copy config\agent_config.cloud-example.json config\agent_config.json` then set the key env.

VM -> Windows Ollama: host IP only (not Kali IP). Always use the `--flag` form for `agents config set`.

## Agent loop

`python recon.py agents <target>` is the scheduler. The full write-up is [USAGE.md](USAGE.md) section 10.

The planner returns one to three modules. Python runs those reconkit stages. The tool step does not call the model. The loop continues while any runnable module is outside `skip_if_chosen`, and it stops at `max_steps` (default 12). A `done: true` answer does not end the run early. The fallback order is subdomains, dns and httpprobe, tls, crawl, js and params and content, the vuln modules, then screenshots.

`alive.txt` with no lines holds back tls, wellknown, crawl, content, bypass403, cors, nuclei, and screenshots. `urls.txt` with no lines holds back the URL modules (js, params, xss, sqli, graphql, and the rest listed in USAGE).

Completed modules live in `~/.reconkit/output/<target>/agent_state.json`. A non-empty output file from a normal scan counts as complete. `--dry-run` does not leave those marks behind when the output file is missing.

The planner loads the skill files only. `phase-06-triage.md` loads once, on the analyst call that writes `agent_report.md`.

## Agent skill suite

Inputs reviewed: **Bug-Bounty-Agents**, **bughunter-ai**, **claude-bug-bounty**,
**Claude-BugHunter** (under `git_skills/`, gitignored). Runtime packs live in `skills/`.

### Core (always role-routed)

| Skill | Purpose |
|-------|---------|
| `reconkit-bug-bounty` | Master pipeline + scope rules |
| `reconkit-efficiency` | Local/cloud token budgets (<=3 modules/step) |
| `reconkit-fp-eval` | C0-C4 tiers, kill-fast FPs |
| `reconkit-exploit-prove` | Canary PoCs + prove technique map |
| `reconkit-triage-gate` | Pre-report 7-gate / N/A prevention |

| Role | Skill files loaded for that call |
|------|----------------------------------|
| planner | bug-bounty + efficiency, plus one matching vuln file |
| specialist | bug-bounty, plus one matching vuln file |
| analyst | fp-eval + triage-gate + exploit-prove, plus one matching vuln file |
| critic | fp-eval + triage-gate, plus one matching vuln file |
| review | fp-eval, plus one vuln file for that phase |
| prove | fp-eval + exploit-prove, plus one matching vuln file |

### On-demand vuln skill (one file per call)

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
C0 noise -> drop
C1 scanner -> prove or manual
C2 canary confirmed -> PoC draft
C3 impact (human) -> triage-gate
C4 report-ready
```

```bash
python recon.py agents    # shows suite by role + surface list
# RECON_AGENT_SKILL=reconkit-bug-bounty   # default
# RECON_AGENT_SKILL=off
# RECON_AGENT_SKILL_EXTRA=reconkit-efficiency
# RECON_AGENT_SKILL_MAX=8000
# RECON_AGENT_SKILL_SURFACE=1
# RECON_AGENT_HUNT_PHASE=auto | off | phase-00-recon
```

Hunting prompts in `skills/bug-bounty-hunting-prompts/phases/` are attached
in full, unchanged, on the analyst, review, and critic calls. The planner
uses the skill files and does not reload those phase files on every step.
`python recon.py agents` prints the map.

### Worked example

```bash
# Surface XSS -> mini-skill reconkit-vuln-xss injects for specialist/analyst
python recon.py agents run --target example.com --modules xss --max-steps 4
python recon.py findings reindex
python recon.py prove run --target example.com --technique xss_reflect
# confirmed proof ~= C2; write impact manually for C3; critic for triage-gate
```

Details: **`skills/README.md`**  /  **`skills/SKILLS_INDEX.md`**  /  **[USAGE.md](USAGE.md#11-agent-skills)**.

**Exploit path:** C1 -> prove (C2) -> PoC draft -> human impact (C3) -> triage (C4).  
No reverse shells / dumps / spray lists in the default path.

## Safety

Detection + safe validation by default. No sqlmap / shells / dumps.  
Scope gate on recon, prove run, and agents.  
Cloud keys never committed.
