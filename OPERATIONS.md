# reconkit v3.0.0 â€” Complete operations catalog

Every user-facing operation the toolkit supports, with **CLI** and **shell** examples.

| Document | Role |
|----------|------|
| **[OPERATIONS.md](OPERATIONS.md)** (this file) | Exhaustive command/API catalog |
| **[WORKFLOW.md](WORKFLOW.md)** | Ordered hunt: setup → recon → prove → graph → agents → report |
| **[USAGE.md](USAGE.md)** | Architecture, configs, modules, skills, troubleshooting |
| **[AGENTS.md](AGENTS.md)** | LLM / skills / program / prove quick start |
| **[skills/README.md](skills/README.md)** | Skill suite + C0–C4 confidence model |

**Project root:** `the Reconkit project root`  
**Replace** `example.com` with a domain you are **authorized** to test.

---

## Table of contents

1. [Entry points](#1-entry-points)
2. [Global flags (reconkit)](#2-global-flags-reconkit)
3. [Setup & environment](#3-setup--environment)
4. [Authorization (scope)](#4-authorization-scope)
5. [API keys](#5-api-keys)
6. [Recon pipeline](#6-recon-pipeline)
7. [Interactive shell (all slash commands)](#7-interactive-shell-all-slash-commands)
8. [Findings index](#8-findings-index)
9. [Program profiles (scoring)](#9-program-profiles-scoring)
10. [Safe prove / validation](#10-safe-prove--validation)
11. [Attack graph](#11-attack-graph)
12. [Dashboard & HTTP API](#12-dashboard--http-api)
13. [Multi-agent LLM (local + cloud)](#13-multi-agent-llm)
14. [Agent skill suite (core + on-demand)](#14-agent-skill-suite-core--on-demand)
15. [Tier A–D analyst tools](#15-tier-ad-analyst-tools)
16. [Playbooks & background jobs](#16-playbooks--background-jobs)
17. [Plugins](#17-plugins)
18. [Help discovery](#18-help-discovery)

---

## 1. Entry points

| Launcher | Purpose |
|----------|---------|
| `python recon_shell.py` | Interactive cyber shell (recommended) |
| `python reconkit.py …` | CLI: setup, scope, run, findings, prove, dashboard |
| `python recon_prove.py …` | Safe validation only |
| `python recon_agents.py …` | Multi-agent LLM recon |
| `python recon_dashboard.py` | Web UI (recon / proofs / graph / insights) |
| `python -m shell` | Same as `recon_shell.py` |
| `python -m agents` | Same as `recon_agents.py` |

```bash
cd /path/to/Bug_Bounty/the Reconkit project root
# Windows:
cd C:\Users\<you>\GitHub\Bug_Bounty\the Reconkit project root

pip install prompt_toolkit colorama
python recon_shell.py
python reconkit.py --version
```

---

## 2. Global flags (reconkit)

Must appear **before** the subcommand.

| Flag | Meaning | Example |
|------|---------|---------|
| `-v 0` / `--verbose 0` | Quiet | `python reconkit.py -v 0 run --target example.com` |
| `-v 1` | Normal (default) | `python reconkit.py -v 1 modules` |
| `-v 2` | Debug + timing | `python reconkit.py -v 2 run --target example.com --modules subdomains` |
| `-v 3` | Live tool stdout/stderr | `python reconkit.py -v 3 run --target example.com --modules nuclei` |
| `--debug` | Same as `-v 2` | `python reconkit.py --debug verify` |
| `--version` | Print version | `python reconkit.py --version` |
| `-h` / `--help` | Help | `python reconkit.py -h` Â· `python reconkit.py run -h` |

Shell equivalent for verbosity:

```text
/verbose 0
/verbose 1
/verbose 2
/verbose 3
/verbose live
/verbose -h
```

---

## 3. Setup & environment

### 3.1 checkenv

```bash
python reconkit.py checkenv
```

```text
/checkenv
/env
/checkenv -h
```

### 3.2 setup

```bash
python reconkit.py setup
# Apply PATH lines printed (Go bin, Cargo bin, Scripts), open a NEW terminal
```

```text
/setup
/install
/setup --help
```

### 3.3 verify

```bash
python reconkit.py verify
```

```text
/verify
/verify -h
```

### 3.4 wordlists

```bash
python reconkit.py wordlists
```

```text
/wordlists
/wl
```

---

## 4. Authorization (scope)

**Hard gate:** `run`, `prove run`, and agents refuse targets not in `~/.reconkit/scope.txt`.

### 4.1 scope add

```bash
python reconkit.py scope add example.com
# type: yes
```

```text
/scope add example.com
# type: yes
```

### 4.2 scope list

```bash
python reconkit.py scope list
```

```text
/scope list
```

### 4.3 scope check

```bash
python reconkit.py scope check example.com
```

```text
/scope check example.com
/scope -h
```

---

## 5. API keys

Stored in `~/.reconkit/secrets.env` (never commit).

### 5.1 keys set

```bash
python reconkit.py keys set PDCP_API_KEY <token>
python reconkit.py keys set GITHUB_TOKEN <token>
# also: CENSYS_API_ID, CENSYS_API_SECRET, SECURITYTRAILS_API_KEY, …
```

```text
/keys set PDCP_API_KEY <token>
/key set GITHUB_TOKEN <token>
```

### 5.2 keys list

```bash
python reconkit.py keys list
```

```text
/keys list
```

### 5.3 keys remove

```bash
python reconkit.py keys remove PDCP_API_KEY
```

```text
/keys remove PDCP_API_KEY
/keys -h
```

---

## 6. Recon pipeline

### 6.1 modules (list)

```bash
python reconkit.py modules
```

```text
/modules
/mods
```

| Module | Role |
|--------|------|
| `subdomains` | Passive / API subdomain enum |
| `dns` | dnsx + CNAME takeover candidates |
| `httpprobe` | httpx alive / tech |
| `tls` | tlsx certs / JARM |
| `crawl` | katana / gau / wayback … → URLs |
| `js` | JS URLs + secret/endpoint regex |
| `params` | unfurl + arjun |
| `content` | sensitive paths + ffuf |
| `xss` | gf + kxss + dalfox candidates |
| `sqli` | detection canaries |
| `ssrf_ssti` | metadata SSRF probe + SSTI canary |
| `nuclei` | templates |
| `cloud` | cloud refs + open S3 list check |
| `screenshots` | gowitness |

### 6.2 run (full or partial)

```bash
# Full pipeline
python reconkit.py run --target example.com

# Selected modules (comma-separated, no spaces)
python reconkit.py run --target example.com --modules subdomains,dns,httpprobe
python reconkit.py run --target example.com --modules xss,sqli,ssrf_ssti,nuclei
python reconkit.py -v 3 run --target example.com --modules subdomains
```

```text
/target example.com
/run
/run example.com                          # BACKGROUND by default (job + /pause /stop)
/run example.com --modules subdomains,dns,httpprobe
/run example.com --modules all
/run example.com --modules nuclei
/run example.com --fg                     # foreground (blocks shell; live spinner)
/run example.com --modules subdomains,    # Tab → module list after --modules
/pause Â· /resume Â· /stop Â· /jobs
/run -h
```

**Progress:** multi-tool phases print one status line when a tool starts and **one
bar line when it finishes** (not a stack of bars). Background jobs use log mode
so the shell prompt is not fighting `\r` redraws.

### 6.3 quick / full / scan (shell)

```text
/quick example.com          # subdomains + dns + httpprobe style fast pass
/full example.com           # all modules
/scan                       # interactive module picker
/scan example.com
```

### 6.4 outdir

```text
/outdir
/outdir example.com
/output
/results
```

Lists files under `~/.reconkit/output/<target>/`.

---

## 7. Interactive shell (all slash commands)

### 7.1 Start shell

```bash
python recon_shell.py
python recon_shell.py --target example.com -v 2
python reconkit.py shell --target example.com
```

Needs `pip install prompt_toolkit` for **LIVE** autocomplete (matches above the prompt).

### 7.2 Shell & session

| Command | Examples |
|---------|----------|
| `/help` | `/help` Â· `/help run` Â· `/?` Â· `/h` |
| `/commands` | `/commands` Â· `/cmds` Â· `/ls` |
| `/banner` | `/banner` |
| `/clear` | `/clear` Â· `/cls` |
| `/status` | `/status` Â· `/info` Â· `/whoami` |
| `/verbose` | `/verbose 2` Â· `/v live` Â· `/debug 3` |
| `/target` | `/target example.com` Â· `/t` Â· `/target` (clear/show) |
| `/exit` | `/exit` Â· `/quit` Â· `/q` |
| `/rate` | `/rate` Â· `/rate stealth` Â· `/rate normal` Â· `/rate aggressive` Â· `/polite show` |

### 7.3 Live autocomplete

```text
Type /          → match strip above prompt
Type /co        → /commands  /config
Type /comm      → /commands   Enter runs it
Type /scope     → then space → add list check
/run T --modules  → subdomains dns httpprobe … all  (module values)
/keys set         → PDCP_API_KEY GITHUB_TOKEN …
/config set --provider  → ollama xai anthropic …
Tab             → complete
Ctrl-Space      → force completion menu
/ alone + Enter → numbered slash menu
```

Catalogs: `shell/suggestions.py`.

### 7.4 Inline help (every command)

```text
/<cmd> -h
/<cmd> --help
/<cmd> -?
/<cmd> /?
/<cmd> help
```

Examples: `/run -h` Â· `/prove --help` Â· `/program -h` Â· `/graph help`

---

## 8. Findings index

### 8.1 reindex

```bash
python reconkit.py findings reindex
```

```text
/findings reindex
/reindex
/index reindex
```

Rebuilds `~/.reconkit/index/findings_index.json` and history snapshots for `/diff`.  
**Re-run after** `/program set …` so bounty weights apply.

### 8.2 summary

```bash
python reconkit.py findings summary
python reconkit.py findings summary example.com
# default action is summary:
python reconkit.py findings
python reconkit.py findings example.com
```

```text
/findings
/findings summary
/findings summary example.com
/findings -h
```

---

## 9. Program profiles (scoring)

Profiles: `config/programs/*.json`  
Active: env `RECON_PROGRAM` or `~/.reconkit/active_program.txt`

### 9.1 list

```text
/program list
/prog list
/bb list
```

### 9.2 show active

```text
/program show
/program
/program status
```

### 9.3 set active

```text
/program set default
/program set example-web
```

```bash
# env (optional)
export RECON_PROGRAM=example-web          # Linux/macOS
$env:RECON_PROGRAM="example-web"          # PowerShell
```

Then:

```text
/findings reindex
/notable
```

API:

```bash
curl -s http://127.0.0.1:8787/api/program
```

---

## 10. Safe prove / validation

Policy: `config/exploit_policy.json`  
Outputs: `~/.reconkit/output/<target>/proofs/`

**Never:** sqlmap, shells, dumps, cloud-metadata blasts (unless you misuse OAST config).

### 10.1 policy

```bash
python recon_prove.py policy
python recon_prove.py policy --json
python reconkit.py prove policy
```

```text
/prove policy
```

### 10.2 techniques

```bash
python recon_prove.py techniques
python reconkit.py prove techniques
```

```text
/prove techniques
```

| Technique | What it does |
|-----------|----------------|
| `xss_reflect` | Unique marker + context (html/attr/js/url/encoded) |
| `ssti_math` | `{{7*7}}` → look for `49` |
| `nuclei_recheck` | Local nuclei artifact + light GET |
| `takeover_fingerprint` | DNS/HTTP fingerprints only |
| `ssrf_canary_review` | Evidence review; OAST if `oast_base_url` set |
| `sqli_boolean` | One true/false pair â€” only if `allow_sqli_boolean: true` |

### 10.3 queue

```bash
python recon_prove.py queue --target example.com
python recon_prove.py queue --target example.com --all
python recon_prove.py queue --target example.com --technique xss_reflect --limit 10
python recon_prove.py queue --target example.com --json
python reconkit.py prove queue --target example.com
```

```text
/prove queue
/prove queue example.com
/prove queue example.com --all
/prove queue example.com --technique xss_reflect --limit 10
```

### 10.4 run

```bash
python recon_prove.py run --target example.com --dry-run
python recon_prove.py run --target example.com
python recon_prove.py run --target example.com --technique xss_reflect --limit 5
python reconkit.py prove run --target example.com --dry-run
```

```text
/prove run example.com --dry-run
/prove run example.com
/prove run example.com --technique ssti_math
/prove run example.com --all --limit 20
```

Requires **in-scope** target.

### 10.5 list / show

```bash
python recon_prove.py list
python recon_prove.py list --target example.com
python recon_prove.py list --target example.com --json
python recon_prove.py show --target example.com --id <proof_id>
python reconkit.py prove list --target example.com
python reconkit.py prove show --target example.com --id <proof_id>
```

```text
/prove list
/prove list example.com
/target example.com
/prove show <proof_id>
```

### 10.6 Optional policy knobs

Edit `config/exploit_policy.json`:

```json
{
  "oast_base_url": "https://YOUR.oast.fun",
  "allow_oast_ssrf": true,
  "allow_sqli_boolean": false
}
```

Then re-run `/prove run example.com --technique ssrf_canary_review`.

---

## 11. Attack graph

### 11.1 shell

```text
/graph
/graph summary
/graph show
/graph show example.com
/graph summary example.com --min-score 40
/paths show
```

### 11.2 Python / API

```bash
python -c "from graph import build_graph, graph_summary; g=build_graph(target='example.com', min_score=40); print(graph_summary(g))"

curl -s "http://127.0.0.1:8787/api/graph?target=example.com&min_score=40"
```

### 11.3 Dashboard

Open **Graph** tab → set min score → **Reload graph** → drag nodes → click for detail.

---

## 12. Dashboard & HTTP API

### 12.1 Launch

```bash
python recon_dashboard.py
python recon_dashboard.py --host 0.0.0.0 --port 8787
python recon_dashboard.py --host 127.0.0.1 --no-browser --no-refresh
python reconkit.py dashboard --port 9000 --no-browser
```

```text
/dashboard
/dashboard --port 9000 --no-browser
/dashboard --host 127.0.0.1
/dash
/ui
```

| URL | When |
|-----|------|
| http://127.0.0.1:8787/ | Same machine |
| http://`<VM_IP>`:8787/ | Host browser → dashboard in VM |

Hard-refresh after upgrades: **Ctrl+F5** (cache-bust `app.css?v=8` / `app.js?v=8`).

### 12.2 Typography & console theme (Bridge UI)

| Surface | Font / colors |
|---------|----------------|
| **UI text** | `Helvetica Neue, Inter, ui-sans-serif, system-ui, sans-serif, Apple Color Emoji, Segoe UI Emoji, Segoe UI Symbol, Noto Color Emoji` |
| **Console / evidence / mono** | **JetBrains Mono** (loaded from Google Fonts) |
| **Evidence / file preview boxes** | Solid background `#1a1d24`, muted foreground `#a8b0bd` (not neon green) |

Evidence panels, source previews, and other â€œconsoleâ€ blocks use the mono stack above.

### 12.3 UI tabs & controls

| Control | Action | Example |
|---------|--------|---------|
| **Recon** | Findings table + filters | Filter module=`nuclei`, notable only |
| **Proofs** | Validation proofs | Status=`confirmed`, technique=`xss_reflect` |
| **Graph** | Attack-path force graph | Min score 40+, drag nodes, click detail |
| **Insights** | Bar charts | Severity mix, top modules, score buckets, proof status |
| Targets list | Scope all tabs to one domain | Click `example.com` |
| Live | Poll disk ~4s | Badge shows LIVE ON |
| Reindex | Rebuild findings index | After `/prove run` or recon |
| program: badge | Active BB profile | From `/program set` |

**Graph tab example**

1. Run recon + `/findings reindex`  
2. Open dashboard → **Graph**  
3. Set **Min score** to `40+ (notable)`  
4. Click **Reload graph**  
5. Drag nodes; click a node → detail panel  

**Proofs tab example**

1. `/prove run example.com`  
2. Dashboard → **Proofs**  
3. Filter Status = `confirmed`  
4. Open a row → evidence + impact  

### 12.4 HTTP API

```bash
# Health & live status
curl -s http://127.0.0.1:8787/api/health
curl -s http://127.0.0.1:8787/api/status

# Overview (recon KPIs + proof counts)
curl -s http://127.0.0.1:8787/api/overview
curl -s "http://127.0.0.1:8787/api/overview?target=example.com&notable=1"

# Targets
curl -s http://127.0.0.1:8787/api/targets
curl -s http://127.0.0.1:8787/api/targets/example.com

# Records (findings)
curl -s "http://127.0.0.1:8787/api/records?limit=50&offset=0"
curl -s "http://127.0.0.1:8787/api/records?target=example.com&module=nuclei&severity=high"
curl -s "http://127.0.0.1:8787/api/records?notable=1&q=takeover"
curl -s "http://127.0.0.1:8787/api/findings?type=secret"   # alias

# Proofs
curl -s "http://127.0.0.1:8787/api/proofs?target=example.com"
curl -s "http://127.0.0.1:8787/api/proofs?status=confirmed&technique=xss_reflect"
curl -s http://127.0.0.1:8787/api/proofs/overview
curl -s http://127.0.0.1:8787/api/proofs/example.com/<proof_id>

# Graph & charts & program
curl -s "http://127.0.0.1:8787/api/graph?target=example.com&min_score=40"
curl -s "http://127.0.0.1:8787/api/stats/charts?target=example.com"
curl -s http://127.0.0.1:8787/api/program

# Diff history
curl -s "http://127.0.0.1:8787/api/diff?target=example.com"

# File preview
curl -s "http://127.0.0.1:8787/api/file?target=example.com&path=subdomains.txt"

# Force reindex
curl -s -X POST http://127.0.0.1:8787/api/reindex
```

| Method | Path |
|--------|------|
| GET | `/api/health` |
| GET | `/api/status` |
| GET | `/api/overview` |
| GET | `/api/targets` Â· `/api/targets/<t>` |
| GET | `/api/records` Â· `/api/findings` |
| GET | `/api/proofs` Â· `/api/proofs/overview` Â· `/api/proofs/<t>/<id>` |
| GET | `/api/graph` Â· `/api/attack-graph` |
| GET | `/api/stats/charts` Â· `/api/charts` |
| GET | `/api/program` Â· `/api/programs` |
| GET | `/api/diff?target=` |
| GET | `/api/file?target=&path=` |
| GET | `/api/modules` |
| POST | `/api/reindex` Â· `/api/refresh` |

---

## 13. Multi-agent LLM

Works with **local Ollama** and **cloud** providers (Grok, Claude, Gemini/Gemma, OpenAI, …). Skills apply to both.

### 13.1 providers (local + cloud)

```bash
python recon_agents.py providers
```

| provider | API | Default model | Key env |
|----------|-----|---------------|---------|
| `ollama` | native | qwen3:8b | (none) |
| `xai` / `grok` | OpenAI-compat | grok-2-latest | `XAI_API_KEY` |
| `anthropic` / `claude` | Messages | claude-sonnet-4-20250514 | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI | gpt-4o-mini | `OPENAI_API_KEY` |
| `google` / `gemini` / `gemma` | OpenAI-compat | gemini-2.0-flash / gemma-3-27b-it | `GOOGLE_API_KEY` |
| `openrouter` | OpenAI-compat | (many) | `OPENROUTER_API_KEY` |
| `groq` | OpenAI-compat | llama-3.3-70b-versatile | `GROQ_API_KEY` |
| `deepseek` / `together` / `mistral` / `fireworks` | OpenAI-compat | see `providers` | matching `*_API_KEY` |
| `custom` | OpenAI-compat | you set | `RECON_LLM_API_KEY` |

### 13.2 config

```bash
python recon_agents.py config show
python recon_agents.py config path
python recon_agents.py config init --repo --base-url http://127.0.0.1:11434 --model qwen3:8b
python recon_agents.py config set --provider ollama --base-url http://192.168.1.4:11434 --model qwen3:8b
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py config set --provider anthropic --model claude-sonnet-4-20250514
python recon_agents.py config set --provider google --model gemini-2.0-flash
python recon_agents.py config set --provider openai --model gpt-4o-mini
# Wrong: config set base_url …   (bare keys rejected)
```

```text
/config show
/config set --provider xai --model grok-2-latest
/config set --provider anthropic --model claude-sonnet-4-20250514
/config set --provider ollama --base-url http://192.168.1.4:11434 --model qwen3:8b
/config -h
```

**Flags for set:** `--base-url` Â· `--model` Â· `--provider` Â· `--api-key` Â· `--temperature` Â· `--timeout` Â· `--max-steps` Â· `--openai-compat true|false`

Examples JSON: `config/agent_config.cloud-examples.json` Â· env: `config/agent.env.example`

### 13.3 check-llm

```bash
python recon_agents.py check-llm
python recon_agents.py check-llm --provider xai --model grok-2-latest
python recon_agents.py check-llm --provider anthropic
```

```text
/check-llm
/llm
/ping-llm
```

Expect: `OK â€” model replied: pong` (Ollama also lists local tags).  
Cloud: API key required. Ollama VM: `base_url` = **Windows host IP**.

### 13.4 agents / modules

```bash
python recon_agents.py agents
python recon_agents.py modules
```

```text
/agents
/agent-list
```

### 13.5 run agents

```bash
python recon_agents.py run --target example.com --dry-run
python recon_agents.py run --target example.com
python recon_agents.py run --target example.com --modules subdomains,dns,httpprobe --max-steps 6
python recon_agents.py run --target example.com --approve
python recon_agents.py run --target example.com -v 2
python recon_agents.py run --target example.com --skip-analyst
# Local Ollama override
python recon_agents.py run --target example.com --provider ollama --base-url http://192.168.1.4:11434
# Cloud one-shot (env key must be set)
python recon_agents.py run --target example.com --provider xai --model grok-2-latest
python recon_agents.py run --target example.com --provider anthropic --model claude-sonnet-4-20250514
python recon_agents.py run --target example.com --provider google --model gemini-2.0-flash
```

```text
/agent example.com --dry-run
/agent example.com
/agent example.com --modules subdomains,dns,httpprobe --max-steps 6
/agent example.com --approve
/agent --dry-run
/agent -h
```

Artifacts: `~/.reconkit/output/example.com/agent_state.json`, `agent_report.md`.

---

## 14. Agent skill suite (core + on-demand)

Skills are [Agent Skills](https://agentskills.io)-style `SKILL.md` packs injected into
planner / specialist / analyst / critic system prompts. They work with **any** LLM
provider (Ollama or cloud).

### 14.1 Inspect wiring

```bash
python recon_agents.py agents
# → primary skill path
# → suite by role (planner / specialist / analyst / critic / prove)
# → surface: (on-demand) reconkit-vuln-...
```

### 14.2 Environment

```bash
# Default (on)
export RECON_AGENT_SKILL=reconkit-bug-bounty

# Disable all skill injection
export RECON_AGENT_SKILL=off

# Always merge extra skills
export RECON_AGENT_SKILL_EXTRA=reconkit-efficiency

# Cap injected characters (local small models: lower; cloud: higher OK)
export RECON_AGENT_SKILL_MAX=14000
```

### 14.3 Core skills (always role-routed)

| Skill | Loaded for | Purpose |
|-------|------------|---------|
| `reconkit-bug-bounty` | planner, specialist, analyst | Pipeline, scope, anti-patterns |
| `reconkit-efficiency` | planner | â‰¤3 modules/step, early-stop, token hygiene |
| `reconkit-fp-eval` | planner, specialist, analyst, critic, prove | C0–C4 tiers, kill-fast FPs |
| `reconkit-exploit-prove` | analyst, critic, prove | Canary PoC template + prove technique map |
| `reconkit-triage-gate` | analyst, critic | Pre-report 7-question / N/A prevention |

| Role | Skills (core) |
|------|----------------|
| planner | bug-bounty + efficiency + fp-eval |
| specialist | bug-bounty + fp-eval |
| analyst | bug-bounty + fp-eval + exploit-prove + triage-gate |
| critic | fp-eval + triage-gate + exploit-prove |
| prove | fp-eval + exploit-prove |

### 14.4 On-demand vuln-class mini-skills (max 3 / turn)

Loaded only when **modules** or **context text** match â€” saves tokens.

| Skill | Example triggers |
|-------|------------------|
| `reconkit-vuln-idor` | module `params`; text `user_id`, `/api/v`, BOLA |
| `reconkit-vuln-jwt` | module `js`; text `eyJ`, bearer, JWT |
| `reconkit-vuln-graphql` | module `crawl`; text `graphql`, introspection |
| `reconkit-vuln-ssrf` | module `ssrf_ssti` / `cloud`; text webhook, OAST |
| `reconkit-vuln-xss` | module `xss`; text dalfox, reflected |
| `reconkit-vuln-sqli` | module `sqli`; SQL error strings |
| `reconkit-vuln-takeover` | module `dns` / `nuclei`; CNAME, takeover |
| `reconkit-vuln-secrets` | module `js`; AKIA, private key, webhook |

**Example flow**

```text
# After crawl+js, specialist "content" runs → may inject secrets + jwt skills
/agent example.com --modules crawl,js

# After xss module → injects reconkit-vuln-xss
/agent example.com --modules xss

# Analyst loads surface skills from findings text + completed modules
# (automatic when writing agent_report.md)
```

### 14.5 Confidence model (C0–C4)

| Tier | Meaning | Typical next |
|------|---------|----------------|
| C0 | Noise / N/A class | drop |
| C1 | Scanner candidate | `/prove …` or manual |
| C2 | Canary re-confirmed (prove) | PoC draft |
| C3 | Impact demonstrated | triage-gate |
| C4 | Report-ready | submit |

```text
C1 (nuclei/xss hit)
  → /prove run --technique xss_reflect   → C2 if confirmed
  → PoC markdown (exploit-prove skill)   → still C2 until impact
  → human HITL impact                    → C3
  → triage-gate                          → C4 report
```

### 14.6 Zero-token pre-eval

Analyst runs heuristic eval before the LLM report (`agents/eval.py`):

- Instant C0 kills (missing CSP alone, info-only nuclei, …)
- Suggests `next: prove:xss_reflect` etc. for C1  

### 14.7 Files

```text
skills/
  SKILLS_INDEX.md
  README.md
  reconkit-bug-bounty/SKILL.md + references/
  reconkit-efficiency/SKILL.md
  reconkit-fp-eval/SKILL.md
  reconkit-exploit-prove/SKILL.md
  reconkit-triage-gate/SKILL.md
  reconkit-vuln-idor/SKILL.md
  reconkit-vuln-jwt/SKILL.md
  reconkit-vuln-graphql/SKILL.md
  reconkit-vuln-ssrf/SKILL.md
  reconkit-vuln-xss/SKILL.md
  reconkit-vuln-sqli/SKILL.md
  reconkit-vuln-takeover/SKILL.md
  reconkit-vuln-secrets/SKILL.md
agents/skills.py    # loader
agents/eval.py      # heuristic tiers
```

Research clones (not shipped as runtime): `git_skills/` (gitignored).

---

## 15. Tier A–D analyst tools

### 15.1 notable

```text
/notable
/notable example.com
/notable example.com --limit 30
/top
```

### 15.2 diff

```text
/diff
/diff example.com
/delta example.com
```

Needs â‰¥2 reindexes for that target.

### 15.3 report

```text
/report
/report example.com
/report example.com --all
/draft
```

Writes `report_draft.md` (includes proofs section when present).

### 15.4 doctor

```text
/doctor
/doctor example.com
/diag
```

### 15.5 tips (local RAG)

```text
/tips subdomain takeover
/tips jwt secrets in javascript
/rag open redirect
```

Sources: `bug_bounty_tips.md`, `~/.reconkit/notes/`.

### 15.6 critic (LLM)

```text
/critic
/critic example.com
/review
```

Needs working `/check-llm` and `agent_report.md` or `report_draft.md`.  
Writes `critic_review.md`. Skills (fp-eval + triage-gate + exploit-prove) inject when critic runs.

---

## 16. Playbooks & background jobs

### 16.1 playbook list / run

```text
/playbook list
/pb list
/playbook run quick example.com
/playbook run js-deep
/playbook run vuln-pass example.com
/playbook run prove-prep example.com
/playbook run full example.com
/recipe run passive example.com
```

| Playbook | Modules (summary) |
|----------|-------------------|
| `quick` | subdomains, dns, httpprobe |
| `takeover-first` | subdomains, dns, httpprobe |
| `js-deep` | httpprobe, crawl, js, params |
| `api-surface` | httpprobe, crawl, params, content, nuclei |
| `vuln-pass` | xss, sqli, ssrf_ssti, nuclei, cloud |
| `content-light` | httpprobe, content |
| `full` | all |
| `passive` | subdomains, dns, httpprobe, tls, crawl |
| `ports-hint` | discovery set (no naabu yet) |
| `prove-prep` | surface for later `/prove` |

### 16.2 background jobs + progress

`/run` / `/quick` / `/full` start a **background job by default** (no need for
`--bg`). Use `--fg` to block the shell.

```text
/run example.com --modules subdomains,dns
/run example.com --modules subdomains,dns --fg
/pause
/resume
/stop          # kills in-flight nuclei/httpx/… process groups
/jobs
/jobs list
/jobs status <id>
/job status <id>
```

**`/stop`** sets a stop flag **and** terminates registered tool process groups
(so a long nuclei CVE pack does not keep running). Job status: `stopping` →
`stopped`. Check with `/jobs`.

Progress modes (`progress_ui.py`): **log** for bg jobs (one bar per tool finish);
**live** for exclusive `--fg` TTY. Env: `RECONKIT_PROGRESS=log|live|off`.

---

## 17. Plugins

Drop-in under `plugins/` (example: `plugins/example_hello.py`).

```text
# See plugins/example_hello.py for COMMANDS export shape
# Core shell works with zero plugins
```

---

## 18. Help discovery

```bash
python reconkit.py -h
python reconkit.py run -h
python reconkit.py prove -h
python recon_prove.py -h
python recon_agents.py -h
python recon_agents.py config -h
python recon_agents.py run -h
python recon_dashboard.py -h
python recon_shell.py -h
```

```text
/
/commands
/help
/help prove
/prove -h
/program -h
/graph -h
```

---

## End-to-end example (one hunt)

```bash
cd the Reconkit project root
pip install prompt_toolkit colorama

python reconkit.py checkenv
python reconkit.py setup
# new terminal + PATH
python reconkit.py verify
python reconkit.py wordlists

python reconkit.py scope add example.com    # type yes
python reconkit.py keys set PDCP_API_KEY …  # optional

python recon_shell.py
```

```text
/program set example-web
/target example.com
/verbose 2
/rate normal
/playbook run prove-prep example.com
/findings reindex
/notable example.com --limit 20
/prove queue
/prove run example.com --dry-run
/prove run example.com
/graph show example.com
/report example.com
/dashboard
```

In the browser (Ctrl+F5 once): **Recon** → **Proofs** → **Graph** → **Insights**.  
UI: Helvetica Neue/Inter; evidence console: JetBrains Mono on solid `#1a1d24`.

### Agents â€” local Ollama

```text
/config set --provider ollama --base-url http://192.168.1.4:11434 --model qwen3:8b
/check-llm
/agents
/agent example.com --dry-run
/agent example.com --max-steps 8
/findings reindex
/critic example.com
```

### Agents â€” cloud Grok (example)

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

### Agents â€” cloud Claude (example)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python recon_agents.py config set --provider anthropic --model claude-sonnet-4-20250514
python recon_agents.py check-llm
python recon_agents.py run --target example.com --approve
```

Skills (C0–C4 + surface mini-skills) load automatically for either local or cloud.

---

## Safety reminder

- Written authorization before `/scope add`
- Detection + **safe** validation only by default
- Do not expose dashboard (`0.0.0.0`) to the public internet
- Secrets stay in `~/.reconkit/secrets.env`
- Treat `~/.reconkit/output` as sensitive

Happy (authorized) hunting.
