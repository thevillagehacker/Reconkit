# reconkit v3.0.0 â€” Complete workflow & examples

Ordered hunt: **setup → authorize → recon → program weights → index → prove → graph → dashboard → agents (local/cloud + skills) → report**.

Replace `example.com` with a domain you are **explicitly authorized** to test.

| Document | Role |
|----------|------|
| **[WORKFLOW.md](WORKFLOW.md)** (this file) | Step-by-step hunt with CLI **and** shell examples |
| **[OPERATIONS.md](OPERATIONS.md)** | Exhaustive catalog of **every** command/API |
| **[USAGE.md](USAGE.md)** | Architecture, modules, configs, troubleshooting |
| **[AGENTS.md](AGENTS.md)** | LLM / skills / prove / program pointer |
| **[skills/README.md](skills/README.md)** | Agent skill suite + C0–C4 |
| **[ROADMAP.md](ROADMAP.md)** | What is done vs future |

> **Project root:** `the Reconkit project root` (not v2.1.0 / v2.0.1).

---

## Table of contents

1. [How to drive the toolkit](#1-how-to-drive-the-toolkit)
2. [Enter the project](#2-enter-the-project)
3. [Phase A â€” Setup](#3-phase-a--setup)
4. [Phase B â€” Verify](#4-phase-b--verify)
5. [Phase C â€” Wordlists & API keys](#5-phase-c--wordlists--api-keys)
6. [Phase D â€” Scope](#6-phase-d--scope)
7. [Phase E â€” Discover modules & help](#7-phase-e--discover-modules--help)
8. [Phase F â€” Verbosity & rate](#8-phase-f--verbosity--rate)
9. [Phase G â€” Run recon](#9-phase-g--run-recon)
10. [Phase H â€” Program profile & findings index](#10-phase-h--program-profile--findings-index)
11. [Phase I â€” Notable, diff, doctor, tips](#11-phase-i--notable-diff-doctor-tips)
12. [Phase J â€” Prove (safe validation)](#12-phase-j--prove-safe-validation)
13. [Phase K â€” Attack graph](#13-phase-k--attack-graph)
14. [Phase L — Dashboard (Scan / Findings / Inbox / Proofs / Graph / Insights)](#14-phase-l--dashboard)
15. [Phase M â€” Multi-agent LLM (local + cloud + skills)](#15-phase-m--multi-agent-llm-local--cloud--skills)
16. [Phase N â€” Report, critic, jobs](#16-phase-n--report-critic-jobs)
17. [Phase O â€” Session utilities](#17-phase-o--session-utilities)
18. [Copy-paste full hunts](#18-copy-paste-full-hunts)
19. [Safety checklist](#19-safety-checklist)
20. [See also](#20-see-also)

---

## 1. How to drive the toolkit

| Style | Launch |
|-------|--------|
| **A. Interactive shell** (recommended) | `python recon_shell.py` |
| **B. CLI one-shots** | `python reconkit.py …` / `recon_prove.py` / `recon_agents.py` |
| **C. Dashboard** | `python recon_dashboard.py` |

Every shell command supports:

```text
/<command> -h
/<command> --help
```

Full catalog: **[OPERATIONS.md](OPERATIONS.md)**.

---

## 2. Enter the project

```bash
# Linux / macOS / Kali
cd ~/Bug_Bounty/the Reconkit project root

# Windows PowerShell
cd C:\Users\<you>\GitHub\Bug_Bounty\the Reconkit project root

pip install prompt_toolkit colorama
python reconkit.py --version
# → reconkit 3.0.0
```

---

## 3. Phase A â€” Setup

### CLI

```bash
pip install prompt_toolkit colorama

python reconkit.py checkenv
python reconkit.py setup
# Apply PATH lines (Go bin, Cargo bin, user Scripts)
# Open a NEW terminal, cd back to v3.0.0
```

### Shell

```text
python recon_shell.py

â–¸ /checkenv
â–¸ /setup
â–¸ /checkenv -h
â–¸ /setup --help
```

---

## 4. Phase B â€” Verify

### CLI

```bash
python reconkit.py verify
python reconkit.py -v 2 verify
```

### Shell

```text
â–¸ /verify
â–¸ /verify -h
â–¸ /status
```

---

## 5. Phase C â€” Wordlists & API keys

### Wordlists

```bash
python reconkit.py wordlists
```

```text
â–¸ /wordlists
â–¸ /wl
```

### API keys (optional)

```bash
python reconkit.py keys set PDCP_API_KEY <token>
python reconkit.py keys set GITHUB_TOKEN <token>
python reconkit.py keys list
python reconkit.py keys remove PDCP_API_KEY
```

```text
â–¸ /keys set PDCP_API_KEY <token>
â–¸ /keys list
â–¸ /keys remove PDCP_API_KEY
â–¸ /keys -h
```

Keys live in `~/.reconkit/secrets.env` only.

---

## 6. Phase D â€” Scope

**Required** before `run` / `prove run` / agents.

### CLI

```bash
python reconkit.py scope add example.com
# Confirm: yes

python reconkit.py scope list
python reconkit.py scope check example.com
```

### Shell

```text
â–¸ /scope add example.com
# type yes
â–¸ /scope list
â–¸ /scope check example.com
â–¸ /scope -h
```

---

## 7. Phase E â€” Discover modules & help

### List modules

```bash
python reconkit.py modules
```

```text
â–¸ /modules
â–¸ /mods
```

### Help & menus

```text
â–¸ /help
â–¸ /help run
â–¸ /commands
â–¸ /                 # numbered menu (Enter after /)
â–¸ /co               # LIVE filter: /commands /config
â–¸ /run -h
â–¸ /prove -h
â–¸ /program -h
â–¸ /graph -h
```

CLI:

```bash
python reconkit.py -h
python reconkit.py run -h
python reconkit.py prove -h
python recon_prove.py -h
python recon_agents.py -h
```

---

## 8. Phase F â€” Verbosity & rate

| Level | Name | Output |
|------:|------|--------|
| 0 | quiet | Banners + OK/WARN/FAIL |
| 1 | normal | Default |
| 2 | debug | Timing, exit codes, file diffs |
| 3 | live | Full tool streams |

### CLI (flag **before** subcommand)

```bash
python reconkit.py -v 0 run --target example.com --modules subdomains
python reconkit.py -v 1 run --target example.com --modules subdomains,dns,httpprobe
python reconkit.py -v 2 run --target example.com --modules subdomains
python reconkit.py -v 3 run --target example.com --modules nuclei
python reconkit.py --debug run --target example.com --modules dns
```

### Shell

```text
â–¸ /verbose 0
â–¸ /verbose 1
â–¸ /verbose 2
â–¸ /verbose 3
â–¸ /verbose live
â–¸ /rate show
â–¸ /rate stealth
â–¸ /rate normal
â–¸ /rate aggressive
```

---

## 9. Phase G â€” Run recon

Set session target (shell):

```text
â–¸ /target example.com
â–¸ /t example.com
```

### G.1 Quick pass

```bash
python reconkit.py run --target example.com --modules subdomains,dns,httpprobe
```

```text
â–¸ /quick example.com
â–¸ /playbook run quick example.com
â–¸ /run example.com --modules subdomains,dns,httpprobe
```

### G.2 Selected modules

```bash
python reconkit.py run --target example.com \
  --modules crawl,js,params,xss,sqli,ssrf_ssti,nuclei,cloud
```

```text
â–¸ /run example.com --modules crawl,js,params,xss,sqli,ssrf_ssti,nuclei,cloud
â–¸ /playbook run prove-prep example.com
â–¸ /playbook run vuln-pass example.com
â–¸ /playbook run js-deep example.com
```

### G.3 Full pipeline

```bash
python reconkit.py run --target example.com
# modules default to all
```

```text
â–¸ /full example.com
â–¸ /run example.com --modules all
â–¸ /playbook run full example.com
```

### G.4 Interactive picker

```text
â–¸ /scan
â–¸ /scan example.com
```

### G.5 Background job

```text
â–¸ /run example.com --modules subdomains,dns,httpprobe --bg
â–¸ /jobs
â–¸ /jobs status <id>
```

### G.6 Resume, multi-scope, authenticated recon

```text
/session set --cookie "sid=abc"
/run example.com --resume
/run --scope-all --modules subdomains,dns,httpprobe
/har import capture.har example.com
/playbook run hunter example.com
/playbook run auth-surface example.com
```

`--resume` skips stages whose primary output already exists. `--scope-all`
runs every root in `~/.reconkit/scope.txt`. Session cookies are sent on httpx
and prove requests. Full hunter extras: **[HUNTER.md](HUNTER.md)**.

### G.7 Where results land

```text
~/.reconkit/output/example.com/
  subdomains.txt, alive.txt, urls.txt, …
  proofs/          # after prove
```

```text
â–¸ /outdir example.com
â–¸ /output
```

---

## 10. Phase H â€” Program profile & findings index

### H.1 Choose program weights

```text
â–¸ /program list
â–¸ /program show
â–¸ /program set example-web
â–¸ /program set default
```

```bash
export RECON_PROGRAM=example-web   # optional
```

Profiles: `config/programs/default.json`, `config/programs/example-web.json`.

### H.2 Reindex (apply scores + history snapshot)

```bash
python reconkit.py findings reindex
python reconkit.py findings summary
python reconkit.py findings summary example.com
```

```text
â–¸ /findings reindex
â–¸ /findings
â–¸ /findings summary example.com
â–¸ /reindex
```

**Always reindex after** recon waves and after `/program set`.

---

## 11. Phase I â€” Notable, diff, doctor, tips

```text
â–¸ /notable
â–¸ /notable example.com
â–¸ /notable example.com --limit 30
â–¸ /top

â–¸ /diff example.com
# needs two reindexes for that target

â–¸ /doctor
â–¸ /doctor example.com

â–¸ /tips subdomain takeover
â–¸ /tips jwt in javascript
```

---

## 12. Phase J â€” Prove (safe validation)

Policy: `config/exploit_policy.json`  
Safe by default â€” markers/canaries only.

### J.1 Policy & techniques

```bash
python recon_prove.py policy
python recon_prove.py techniques
python reconkit.py prove policy
```

```text
â–¸ /prove policy
â–¸ /prove techniques
â–¸ /prove -h
```

Techniques: `xss_reflect` Â· `ssti_math` Â· `nuclei_recheck` Â· `takeover_fingerprint` Â· `ssrf_canary_review` Â· `sqli_boolean` (off until policy allows).

### J.2 Optional OAST / SQLi (policy file)

```json
{
  "oast_base_url": "https://YOUR.oast.fun",
  "allow_oast_ssrf": true,
  "allow_sqli_boolean": false
}
```

Hunter prove extras (`jwt_inspect`, `cors_origin`, `graphql_typename`,
`redirect_canary`, `idor_session_diff`) are listed in [HUNTER.md](HUNTER.md)
and `/prove techniques`.

### J.3 Queue & run

```bash
python recon_prove.py queue --target example.com
python recon_prove.py run --target example.com --dry-run
python recon_prove.py run --target example.com
python recon_prove.py run --target example.com --technique xss_reflect --limit 10
python recon_prove.py list --target example.com
python recon_prove.py show --target example.com --id <proof_id>
```

```text
â–¸ /prove queue
â–¸ /prove queue example.com
â–¸ /prove queue example.com --all
â–¸ /prove run example.com --dry-run
â–¸ /prove run example.com
â–¸ /prove run example.com --technique ssti_math
â–¸ /prove list example.com
â–¸ /target example.com
â–¸ /prove show <id>
```

### J.4 Prep playbook then prove

```text
â–¸ /playbook run prove-prep example.com
â–¸ /findings reindex
â–¸ /prove queue
â–¸ /prove run example.com
```

Proofs: `~/.reconkit/output/example.com/proofs/`.

---

## 13. Phase K â€” Attack graph

### Shell

```text
â–¸ /graph
â–¸ /graph summary
â–¸ /graph show
â–¸ /graph show example.com
â–¸ /graph summary example.com --min-score 40
```

### Python / API

```bash
python -c "from graph import build_graph, graph_summary; print(graph_summary(build_graph(target='example.com', min_score=40)))"

curl -s "http://127.0.0.1:8787/api/graph?target=example.com&min_score=40" | head
```

Nodes: target Â· host Â· url Â· vuln Â· secret Â· proof Â· module  
Edges: has_asset Â· exposes Â· proved_by Â· from_module Â· …

---

## 14. Phase L â€” Dashboard

### Launch

```bash
python recon_dashboard.py
python recon_dashboard.py --host 0.0.0.0 --port 8787
python reconkit.py dashboard --no-browser
```

```text
â–¸ /dashboard
â–¸ /dashboard --port 9000 --no-browser
â–¸ /dash
```

Browse: http://127.0.0.1:8787/ (or `http://<VM_IP>:8787/` from host).  
**Ctrl+F5** after upgrades (cache-bust `app.css?v=8` / `app.js?v=8`).

### Typography & console theme (Bridge UI)

| Surface | Font / colors |
|---------|----------------|
| **UI chrome / tables / labels** | `Helvetica Neue`, **Inter**, system UI sans |
| **Evidence / file preview / mono** | **JetBrains Mono** (Google Fonts) |
| **Console boxes** | Background `#1a1d24`, text `#a8b0bd` (muted solid â€” not neon green) |

Open a recon row → **source preview** and Proofs **evidence** panels use the mono console theme.

### Tabs

**Scan** · **Findings** · **Inbox** (C1+ hunter triage) · **Proofs** · **Graph** · **Insights**

### Tabs (detail)

| Tab | Use | Example walkthrough |
|-----|-----|---------------------|
| **Scan** | Live module tiles | Watch current phase while `/run` is backgrounded |
| **Findings** | Filter module/severity/type/notable; open evidence | Module=`nuclei`, Notable only → open high-score row |
| **Inbox** | C1+ hunter triage + suggested prove technique | Same as `/inbox` |
| **Proofs** | Confirmed / needs_manual / … proofs | Status=`confirmed`, technique=`xss_reflect` |
| **Graph** | Force-directed attack paths; drag nodes; click detail | Min score `40+`, Reload graph, click edge/node |
| **Insights** | Bar charts: severity, modules, score buckets, proof status | Pick target → compare severity vs proof status |

### Controls

- **Live** â€” poll disk ~4s (badge LIVE ON)  
- **Reindex** â€” rebuild index without restart (after recon or `/prove run`)  
- **program:** badge â€” active BB profile from `/program set`  
- Target sidebar â€” scopes **all** tabs  

### Useful API

```bash
curl -s http://127.0.0.1:8787/api/health
curl -s http://127.0.0.1:8787/api/overview
curl -s "http://127.0.0.1:8787/api/records?target=example.com&notable=1"
curl -s "http://127.0.0.1:8787/api/proofs?status=confirmed"
curl -s "http://127.0.0.1:8787/api/graph?target=example.com&min_score=40"
curl -s "http://127.0.0.1:8787/api/stats/charts?target=example.com"
curl -s http://127.0.0.1:8787/api/program
curl -s -X POST http://127.0.0.1:8787/api/reindex
```

Full API table: **OPERATIONS.md Â§12**.

---

## 15. Phase M â€” Multi-agent LLM (local + cloud + skills)

Agents use a unified client (`agents/llm.py`): **Ollama** locally **or** cloud
providers (Grok, Claude, Gemini/Gemma, OpenAI, OpenRouter, Groq, …).  
Skill packs inject by **role** and **surface** (vuln class) for fewer FPs.

### M.1 List providers

```bash
python recon_agents.py providers
```

| provider | API style | Default model | Key env |
|----------|-----------|---------------|---------|
| `ollama` | native | `qwen3:8b` | (none) |
| `xai` / `grok` | OpenAI-compat | `grok-2-latest` | `XAI_API_KEY` |
| `anthropic` / `claude` | Messages | `claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI | `gpt-4o-mini` | `OPENAI_API_KEY` |
| `google` / `gemini` | OpenAI-compat | `gemini-2.0-flash` | `GOOGLE_API_KEY` |
| `gemma` | OpenAI-compat | `gemma-3-27b-it` | `GOOGLE_API_KEY` |
| `openrouter` | OpenAI-compat | many | `OPENROUTER_API_KEY` |
| `groq` | OpenAI-compat | `llama-3.3-70b-versatile` | `GROQ_API_KEY` |
| `deepseek` / `together` / `mistral` / `fireworks` | OpenAI-compat | see `providers` | matching `*_API_KEY` |
| `custom` | OpenAI-compat | you set | `RECON_LLM_API_KEY` |

Templates: **[config/CLOUD_LLM_SETUP.md](config/CLOUD_LLM_SETUP.md)** Â·  
`config/agent_config.cloud-example.json` (drop-in) Â·  
`config/agent_config.cloud-presets.json` Â·  
`config/agent_config.cloud-examples.json` Â· `config/agent.env.example`.

### M.2 Configure (always `--flag` form)

```bash
python recon_agents.py config show
python recon_agents.py config path
# Local Ollama (VM → Windows: use HOST IP, not Kali IP)
python recon_agents.py config set --provider ollama \
  --base-url http://192.168.1.4:11434 --model qwen3:8b
# Cloud â€” set env key first, then switch provider (model preset fills in)
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py config set --provider anthropic --model claude-sonnet-4-20250514
python recon_agents.py config set --provider google --model gemini-2.0-flash
python recon_agents.py config set --provider openai --model gpt-4o-mini
```

```text
â–¸ /config show
â–¸ /config path
â–¸ /config set --provider ollama --base-url http://192.168.1.4:11434 --model qwen3:8b
â–¸ /config set --provider xai --model grok-2-latest
â–¸ /config set --provider anthropic --model claude-sonnet-4-20250514
â–¸ /config set --model qwen3:8b --timeout 300
```

**Wrong (rejected):** `/config set base_url http://…` (bare keys).

**VM → Windows Ollama:** `base_url` = host IP only.  
Windows: `setx OLLAMA_HOST 0.0.0.0`, restart Ollama, firewall 11434.

### M.3 Ping

```bash
python recon_agents.py check-llm
python recon_agents.py check-llm --provider xai --model grok-2-latest
python recon_agents.py check-llm --provider anthropic
```

```text
â–¸ /check-llm
â–¸ /llm
â–¸ /ping-llm
```

Expect: `OK â€” model replied: pong`. Cloud needs the API key in the environment.

### M.4 Inspect agents + skill suite

```bash
python recon_agents.py agents
# → specialists + primary skill path + suite by role + surface mini-skills
python recon_agents.py modules
```

```text
â–¸ /agents
â–¸ /agent-list
```

### M.5 Agent skill suite (automatic)

Skills are Agent Skills–style packs under `skills/` injected into system prompts.
They work with **any** provider (Ollama or cloud).

| Role | Core skills loaded |
|------|--------------------|
| planner | bug-bounty + efficiency + fp-eval |
| specialist | bug-bounty + fp-eval |
| analyst | bug-bounty + fp-eval + exploit-prove + triage-gate |
| critic | fp-eval + triage-gate + exploit-prove |

**On-demand mini-skills** (max **3 per turn**) load when modules/context match:

| Skill | Example trigger |
|-------|-----------------|
| `reconkit-vuln-xss` | module `xss` |
| `reconkit-vuln-sqli` | module `sqli` |
| `reconkit-vuln-ssrf` | module `ssrf_ssti` / cloud |
| `reconkit-vuln-jwt` / `secrets` | module `js` |
| `reconkit-vuln-idor` | module `params` / crawl |
| `reconkit-vuln-takeover` | module `dns` / nuclei |
| `reconkit-vuln-graphql` | crawl + â€œgraphqlâ€ text |

**Confidence pipeline (C0–C4)**

```text
C0 noise → drop
C1 scanner hit → /prove or manual
C2 canary confirmed (prove) → PoC draft
C3 impact (human HITL) → triage-gate
C4 report-ready
```

Env controls:

```bash
# default on
export RECON_AGENT_SKILL=reconkit-bug-bounty
# disable injection
export RECON_AGENT_SKILL=off
# always merge extras
export RECON_AGENT_SKILL_EXTRA=reconkit-efficiency
# char budget (lower for small local models)
export RECON_AGENT_SKILL_MAX=14000
```

Details: **skills/README.md** Â· **skills/SKILLS_INDEX.md** Â· **OPERATIONS.md Â§14**.

### M.6 Run agents

```bash
python recon_agents.py run --target example.com --dry-run
python recon_agents.py run --target example.com --max-steps 8
python recon_agents.py run --target example.com --modules subdomains,dns,httpprobe --max-steps 6
python recon_agents.py run --target example.com --approve
python recon_agents.py run --target example.com --skip-analyst
# one-shot provider override (does not rewrite config file)
python recon_agents.py run --target example.com --provider xai --model grok-2-latest
python recon_agents.py run --target example.com --provider anthropic
python recon_agents.py run --target example.com --provider ollama \
  --base-url http://192.168.1.4:11434
```

```text
â–¸ /agents
â–¸ /agent example.com --dry-run
â–¸ /agent example.com
â–¸ /agent example.com --modules subdomains,dns,httpprobe --max-steps 6
â–¸ /agent example.com --approve
â–¸ /agent -h
```

Artifacts: `~/.reconkit/output/example.com/agent_state.json`, `agent_report.md`.

Then:

```text
â–¸ /findings reindex
â–¸ /prove queue
â–¸ /prove run example.com
â–¸ /outdir example.com
```

### M.7 Cloud end-to-end examples

**Grok (xAI)**

```bash
export XAI_API_KEY=xai-...
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py check-llm
python recon_agents.py run --target example.com --max-steps 8
```

```text
/config set --provider xai --model grok-2-latest
/check-llm
/agent example.com --max-steps 8
```

**Claude (Anthropic)**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python recon_agents.py config set --provider anthropic --model claude-sonnet-4-20250514
python recon_agents.py check-llm
python recon_agents.py run --target example.com --approve
```

**Gemini / Gemma (Google)**

```bash
export GOOGLE_API_KEY=...
python recon_agents.py config set --provider google --model gemini-2.0-flash
# or Gemma:
python recon_agents.py config set --provider gemma --model gemma-3-27b-it
python recon_agents.py check-llm
```

**OpenRouter (one key → many models)**

```bash
export OPENROUTER_API_KEY=...
python recon_agents.py config set --provider openrouter \
  --model anthropic/claude-3.5-sonnet
python recon_agents.py check-llm
```

---

## 16. Phase N â€” Report, critic, jobs

```text
â–¸ /report example.com
â–¸ /report example.com --all
# → report_draft.md (includes proofs when present)

â–¸ /critic example.com
# needs LLM + agent_report.md or report_draft.md
# critic loads fp-eval + triage-gate + exploit-prove skills
# → critic_review.md

â–¸ /run example.com --modules nuclei --bg
â–¸ /jobs
â–¸ /jobs status <id>
```

---

## 17. Phase O — Session utilities

```text
/status
/banner
/clear
/target
/session show
/session set --cookie "sid=…"
/inbox
/evidence example.com
/wordlist-target example.com
/exit
```

---

## 18. Copy-paste full hunts

### 18.1 First day (CLI)

```bash
cd path/to/Reconkit
pip install prompt_toolkit colorama
python reconkit.py checkenv
python reconkit.py setup
# new terminal + PATH
python reconkit.py verify
python reconkit.py wordlists
python reconkit.py scope add example.com
python reconkit.py run --target example.com --modules subdomains,dns,httpprobe,crawl,jsintel,apis,nuclei
python reconkit.py findings reindex
python recon_prove.py queue --target example.com
python recon_prove.py run --target example.com --dry-run
python recon_prove.py run --target example.com
python recon_dashboard.py
```

### 18.2 Full shell hunt (v3.0 features)

```text
python recon_shell.py

/program set example-web
/scope add example.com
/target example.com
/verbose 2
/rate normal
/playbook run prove-prep example.com
/findings reindex
/notable example.com --limit 25
/diff example.com
/prove policy
/prove queue
/prove run example.com --dry-run
/prove run example.com
/graph show example.com
/report example.com
/dashboard
# browser: Recon → Proofs → Graph → Insights
# fonts: UI Helvetica Neue/Inter; evidence JetBrains Mono #1a1d24
/exit
```

### 18.3 Agents + skills + critic (local Ollama)

```bash
python recon_agents.py providers
python recon_agents.py config set --provider ollama \
  --base-url http://192.168.1.4:11434 --model qwen3:8b
python recon_agents.py check-llm
python recon_agents.py agents          # shows skill suite by role
python recon_agents.py run --target example.com --dry-run
python recon_agents.py run --target example.com --max-steps 8
python reconkit.py findings reindex
```

```text
/check-llm
/agents
/agent example.com --max-steps 8
/findings reindex
/prove queue
/prove run example.com
/critic example.com
/report example.com
```

### 18.4 Agents on cloud Grok

```bash
export XAI_API_KEY=xai-...
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py check-llm
python recon_agents.py run --target example.com --max-steps 8
# skills still inject (C0–C4 + surface mini-skills)
```

### 18.5 Surface mini-skill focused pass

```text
# XSS surface → injects reconkit-vuln-xss (among others, max 3)
/agent example.com --modules xss --max-steps 4

# JS secrets / JWT surface
/agent example.com --modules crawl,js --max-steps 4

# Then prove canaries → C2
/findings reindex
/prove run example.com --technique xss_reflect
```

### 18.6 Debug empty stage

```bash
python reconkit.py -v 2 run --target example.com --modules subdomains
python reconkit.py -v 3 run --target example.com --modules subdomains
# ~/.reconkit/logs/debug.log
```

```text
/verbose 3
/run example.com --modules subdomains
/doctor example.com
```

---

## 19. Safety checklist

- [ ] Written authorization before `/scope add`
- [ ] Target appears in `/scope list`
- [ ] Detection-only recon; prove stays **safe** unless you knowingly change policy
- [ ] VM `base_url` = **Windows host IP** for Ollama
- [ ] Cloud API keys only in env / local config (never commit)
- [ ] Dashboard not public (default is localhost; `--host 0.0.0.0` is LAN-reachable)
- [ ] Secrets only in `~/.reconkit/secrets.env`
- [ ] Treat `~/.reconkit/output` as sensitive
- [ ] `allow_sqli_boolean` / OAST only under program RoE
- [ ] Never claim C3/C4 from nuclei alone â€” prove + impact first

---

## 20. See also

| Topic | Where |
|-------|--------|
| Every command + API example | **[OPERATIONS.md](OPERATIONS.md)** |
| Config files, modules detail, troubleshooting | **[USAGE.md](USAGE.md)** |
| LLM / program / prove / skills quick start | **[AGENTS.md](AGENTS.md)** |
| Skill suite design + C0–C4 | **[skills/README.md](skills/README.md)** Â· **[skills/SKILLS_INDEX.md](skills/SKILLS_INDEX.md)** |
| Hunter extras (session, HAR, inbox, extra modules) | **[HUNTER.md](HUNTER.md)** |
| Implemented vs future | **[ROADMAP.md](ROADMAP.md)** |

Happy (authorized) hunting.
