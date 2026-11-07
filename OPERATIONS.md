# reconkit v3.0.0 -- Complete operations catalog

Every user-facing operation the toolkit supports, with **CLI** and **shell** examples.

| Document | Role |
|----------|------|
| **[OPERATIONS.md](OPERATIONS.md)** (this file) | Exhaustive command/API catalog |
| **[WORKFLOW.md](WORKFLOW.md)** | Ordered hunt: setup -> recon -> prove -> graph -> agents -> report |
| **[USAGE.md](USAGE.md)** | Architecture, configs, modules, skills, troubleshooting |
| **[AGENTS.md](AGENTS.md)** | LLM / skills / program / prove quick start |
| **[HUNTER.md](HUNTER.md)** | Session, HAR, inbox, extra modules |
| **[skills/README.md](skills/README.md)** | Skill suite + C0-C4 confidence model |

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
12. [Reading results](#12-reading-results)
13. [Multi-agent LLM (local + cloud)](#13-multi-agent-llm)
14. [Agent skill suite (core + on-demand)](#14-agent-skill-suite-core--on-demand)
15. [Tier A-D analyst tools](#15-tier-ad-analyst-tools)
16. [Playbooks & background jobs](#16-playbooks--background-jobs)
17. [Plugins](#17-plugins)
18. [Help discovery](#18-help-discovery)
19. [Hunter extras (session, HAR, inbox, extra modules)](#19-hunter-extras-session-har-inbox-extra-modules)

---

## 1. Entry points

| Launcher | Purpose |
|----------|---------|
| `python recon_shell.py` | Interactive cyber shell (recommended) |
| `python reconkit.py ...` | CLI: setup, scope, run, findings, prove |
| `python recon_prove.py ...` | Safe validation only |
| `python recon_agents.py ...` | Multi-agent LLM recon |
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
| `-h` / `--help` | Help | `python reconkit.py -h`  /  `python reconkit.py run -h` |

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
python reconkit.py scope add example.com --yes    # skip prompt (automation / SSH)
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
# also: CENSYS_API_ID, CENSYS_API_SECRET, SECURITYTRAILS_API_KEY, ...
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
| `permute` | Capped DNS permutations (alterx/dnsgen). dnsx only when dns is not in the same run |
| `dns` | One dnsx pass: records, resolved hosts, CNAME takeover candidates |
| `ports` | In-scope naabu connect-scan + httpx |
| `httpprobe` | httpx alive / tech (session headers; WAF -> stealth) |
| `tls` | tlsx certs / JARM |
| `wellknown` | robots / sitemap / security.txt / OpenID |
| `crawl` | katana / gau / wayback ... -> in-scope URLs |
| `js` | JS URLs + secret/endpoint regex |
| `jsintel` | Sourcemaps, hidden routes, API paths, lib versions |
| `params` | unfurl + arjun |
| `apis` | OpenAPI / GraphQL / IDOR-shaped URLs |
| `content` | sensitive paths + ffuf |
| `bypass403` | Header/path 401/403 probes (no spray) |
| `gfextra` | gf redirect / lfi / interestingparams |
| `xss` | gf + kxss + dalfox candidates |
| `sqli` | detection canaries |
| `ssrf_ssti` | metadata SSRF probe + SSTI canary |
| `redirect` | Open-redirect canary (OAST or `.invalid`) |
| `cors` | CORS ACAO reflection check |
| `graphql` | `{__typename}` endpoint detect (no schema dump) |
| `nuclei` | CVE / takeover / misconfig + tech-tagged pack |
| `cloud` | cloud refs + open S3 list check |
| `takeover_plus` | package.json / dangling JS CDN 404s |
| `osint` | Shodan/Censys **this hostname only** |
| `gitrecon` | GitHub/GitLab URLs + optional trufflehog |
| `screenshots` | gowitness |

### 6.2 run (full or partial)

```bash
# Full pipeline
python reconkit.py run --target example.com

# Selected modules (comma-separated, no spaces)
python reconkit.py run --target example.com --modules subdomains,dns,httpprobe
python reconkit.py run --target example.com --modules xss,sqli,ssrf_ssti,nuclei
python reconkit.py run --target example.com --resume
python reconkit.py run --target example.com --review
python reconkit.py run --scope-all --modules subdomains,dns,httpprobe
python reconkit.py -v 3 run --target example.com --modules subdomains
```

```text
/target example.com
/run
/run example.com                          # BACKGROUND by default (job + /pause /stop)
/run example.com --modules subdomains,dns,httpprobe
/run example.com --modules all
/run example.com --modules nuclei
/run example.com --resume                 # skip stages whose output already exists
/run example.com --review                 # model note per phase -> reviews/
/run --scope-all --modules subdomains,dns,httpprobe
/run example.com --fg                     # foreground (blocks shell; live spinner)
/run example.com --modules subdomains,    # Tab -> module list after --modules
/pause  /  /resume  /  /stop  /  /jobs
/session show  /  /har import  /  /inbox  /  /evidence
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
| `/help` | `/help`  /  `/help run`  /  `/?`  /  `/h` |
| `/commands` | `/commands`  /  `/cmds`  /  `/ls` |
| `/banner` | `/banner` |
| `/clear` | `/clear`  /  `/cls` |
| `/status` | `/status`  /  `/info`  /  `/whoami` |
| `/verbose` | `/verbose 2`  /  `/v live`  /  `/debug 3` |
| `/target` | `/target example.com`  /  `/t`  /  `/target` (clear/show) |
| `/exit` | `/exit`  /  `/quit`  /  `/q` |
| `/rate` | `/rate`  /  `/rate stealth`  /  `/rate normal`  /  `/rate aggressive`  /  `/polite show` |
| `/session` | `/session show`  /  `/session set --cookie "..."`  /  `/session set --cookie-b "..."`  /  `/session clear` |

### 7.3 Live autocomplete

```text
Type /          -> match strip above prompt
Type /co        -> /commands  /config
Type /comm      -> /commands   Enter runs it
Type /scope     -> then space -> add list check
/run T --modules  -> subdomains dns httpprobe ... all  (module values)
/keys set         -> PDCP_API_KEY GITHUB_TOKEN ...
/config set --provider  -> ollama xai anthropic ...
Tab             -> complete
Ctrl-Space      -> force completion menu
/ alone + Enter -> numbered slash menu
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

Examples: `/run -h`  /  `/prove --help`  /  `/program -h`  /  `/graph help`

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
**Re-run after** `/program set ...` so bounty weights apply.

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
| `ssti_math` | `{{7*7}}` -> look for `49` |
| `nuclei_recheck` | Local nuclei artifact + light GET |
| `takeover_fingerprint` | DNS/HTTP fingerprints only |
| `ssrf_canary_review` | Evidence review; OAST if `oast_base_url` set |
| `sqli_boolean` | One true/false pair -- only if `allow_sqli_boolean: true` |
| `jwt_inspect` | Decode JWT header/payload only (no cracking) |
| `cors_origin` | Origin canary; confirm ACAO + credentials |
| `graphql_typename` | POST `{__typename}` only (no schema dump) |
| `redirect_canary` | Bounce to OAST or `.invalid` host |
| `idor_session_diff` | GET same URL with cookie A vs B (set `/session`) |

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
```

### 11.3 Shell

```text
/graph show example.com --min-score 40
```

---

## 12. Reading results

There is no web UI and no HTTP API. Use the shell:

```text
/findings reindex
/findings example.com
/inbox example.com
/prove list example.com
/prove show example.com --id <proof_id>
/graph show example.com --min-score 40
/notable example.com
/diff example.com
/outdir example.com
```

---

## 13. Multi-agent LLM

Works with **local Ollama** and **cloud** providers (Grok, Claude, Gemini/Gemma, OpenAI, ...). Skills apply to both.

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
# Wrong: config set base_url ...   (bare keys rejected)
```

```text
/config show
/config set --provider xai --model grok-2-latest
/config set --provider anthropic --model claude-sonnet-4-20250514
/config set --provider ollama --base-url http://192.168.1.4:11434 --model qwen3:8b
/config -h
```

**Flags for set:** `--base-url`  /  `--model`  /  `--provider`  /  `--api-key`  /  `--temperature`  /  `--timeout`  /  `--max-steps`  /  `--openai-compat true|false`

Examples JSON: `config/agent_config.cloud-examples.json`  /  env: `config/agent.env.example`

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

Expect: `OK -- model replied: pong` (Ollama also lists local tags).  
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

Each `/agent` step asks the model for the next 1 to 3 modules and one prove technique id, or `none`. The id is stored on that step. `/prove run` is still the command that performs the check. `/run` does not ask the model.

---

## 14. Agent skill suite (core + on-demand)

Skills are [Agent Skills](https://agentskills.io)-style `SKILL.md` packs injected into
planner / specialist / analyst / critic system prompts. They work with **any** LLM
provider (Ollama or cloud).

### 14.1 Inspect wiring

```bash
python recon_agents.py agents
# -> primary skill path
# -> suite by role (planner / specialist / analyst / critic / prove)
# -> surface: (on-demand) reconkit-vuln-...
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
export RECON_AGENT_SKILL_MAX=8000
export RECON_AGENT_SKILL_SURFACE=1
```

### 14.3 Core skills (fetched per call)

| Skill | Loaded for | Purpose |
|-------|------------|---------|
| `reconkit-bug-bounty` | planner | Pipeline, scope, anti-patterns |
| `reconkit-efficiency` | planner | <=3 modules/step, early-stop, token hygiene |
| `reconkit-fp-eval` | analyst, critic, review, prove | C0-C4 tiers, kill-fast FPs |
| `reconkit-exploit-prove` | analyst, prove | Canary PoC template + prove technique map |
| `reconkit-triage-gate` | analyst, critic | Pre-report 7-question / N/A prevention |

| Role | Skill files |
|------|-------------|
| planner | bug-bounty + efficiency, plus one matching vuln file |
| analyst | fp-eval + triage-gate + exploit-prove |
| critic | fp-eval + triage-gate |
| review | fp-eval, plus one vuln file for that phase |
| prove | fp-eval + exploit-prove |

### 14.4 On-demand vuln skill file (one per call)

Loaded when a finished module or the current text matches.

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
# After crawl+js, specialist "content" runs -> may inject secrets + jwt skills
/agent example.com --modules crawl,js

# After xss module -> injects reconkit-vuln-xss
/agent example.com --modules xss

# Analyst loads surface skills from findings text + completed modules
# (automatic when writing agent_report.md)
```

### 14.5 Confidence model (C0-C4)

| Tier | Meaning | Typical next |
|------|---------|----------------|
| C0 | Noise / N/A class | drop |
| C1 | Scanner candidate | `/prove ...` or manual |
| C2 | Canary re-confirmed (prove) | PoC draft |
| C3 | Impact demonstrated | triage-gate |
| C4 | Report-ready | submit |

```text
C1 (nuclei/xss hit)
  -> /prove run --technique xss_reflect   -> C2 if confirmed
  -> PoC markdown (exploit-prove skill)   -> still C2 until impact
  -> human HITL impact                    -> C3
  -> triage-gate                          -> C4 report
```

### 14.6 Zero-token pre-eval

Analyst runs heuristic eval before the LLM report (`agents/eval.py`):

- Instant C0 kills (missing CSP alone, info-only nuclei, ...)
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
  bug-bounty-hunting-prompts/   # ADAPTATION.md plus recon, scope, and triage phases
agents/skills.py    # loader
agents/eval.py      # heuristic tiers
```

Research clones (not shipped as runtime): `git_skills/` (gitignored).

---

## 15. Tier A-D analyst tools

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

Needs >=2 reindexes for that target.

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

Sources: `skills/**/*.md`, `~/.reconkit/notes/`.

### 15.6 critic (LLM)

```text
/critic
/critic example.com
/review
```

Needs working `/check-llm` and `agent_report.md` or `report_draft.md`.  
Writes `critic_review.md`. The critic call loads `reconkit-fp-eval` and `reconkit-triage-gate`.

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
| `takeover-first` | subdomains, dns, httpprobe, takeover_plus |
| `js-deep` | httpprobe, crawl, js, jsintel, params |
| `api-surface` | crawl + jsintel + apis + graphql + cors + nuclei |
| `vuln-pass` | xss, sqli, ssrf_ssti, redirect, cors, graphql, nuclei, cloud |
| `content-light` | httpprobe, wellknown, content, bypass403 |
| `full` | all |
| `passive` | subdomains, dns, httpprobe, tls, wellknown, crawl |
| `ports-hint` | subdomains, dns, ports, httpprobe, tls |
| `auth-surface` | crawl + jsintel + apis + bypass403 (set `/session` first) |
| `hunter` | permute, ports, wellknown, jsintel, apis, bypass403, gf extras, takeover+ |
| `prove-prep` | surface for later `/prove` (incl. redirect/cors/graphql) |

### 16.2 background jobs + progress

`/run` / `/quick` / `/full` start a **background job by default** (no need for
`--bg`). Use `--fg` to block the shell.

```text
/run example.com --modules subdomains,dns
/run example.com --modules subdomains,dns --fg
/pause
/resume
/stop          # kills in-flight nuclei/httpx/... process groups
/jobs
/jobs list
/jobs status <id>
/job status <id>
```

**`/stop`** sets a stop flag **and** terminates registered tool process groups
(so a long nuclei CVE pack does not keep running). Job status: `stopping` ->
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
/session -h
/inbox -h
```

---

## 19. Hunter extras (session, HAR, inbox, extra modules)

Full walkthrough: **[HUNTER.md](HUNTER.md)**.

### 19.1 Auth session

```bash
python reconkit.py session show
python reconkit.py session set --cookie "sid=abc" --header "Authorization: Bearer ..."
python reconkit.py session set --cookie-b "sid=other"
python reconkit.py session clear
```

```text
/session
/session set --cookie "sid=abc"
/session set --cookie-b "sid=other" --header "Authorization: Bearer x"
/session clear
```

File: `~/.reconkit/session.json` (chmod 600, never commit). Account B is for
`/prove run --technique idor_session_diff` only.

### 19.2 HAR, evidence, target wordlist

```bash
python reconkit.py har --target example.com --file capture.har
python reconkit.py wordlist-target --target example.com
python reconkit.py evidence --target example.com
python reconkit.py evidence --target example.com --id <finding_id>
```

```text
/har import capture.har example.com
/wordlist-target example.com
/evidence example.com
/inbox example.com
```

### 19.3 Resume and multi-scope

```bash
python reconkit.py run --target example.com --resume
python reconkit.py run --target example.com --force
python reconkit.py run --target example.com --review
python reconkit.py run --scope-all --modules subdomains,dns,httpprobe
```

```text
/run example.com --resume
/run example.com --review
/run --scope-all --modules subdomains,dns,httpprobe
```

`--resume` skips a module when its primary output already exists. `--force`
overrides that. `--scope-all` iterates every root in `~/.reconkit/scope.txt`.
`--review` writes `reviews/<phase>.txt` from the configured model after each
phase and `reviews/summary.txt` when the run finishes. `/stop` skips the summary.

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
python reconkit.py keys set PDCP_API_KEY ...  # optional

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
/notable example.com
```

### Agents -- local Ollama

```text
/config set --provider ollama --base-url http://192.168.1.4:11434 --model qwen3:8b
/check-llm
/agents
/agent example.com --dry-run
/agent example.com --max-steps 8
/findings reindex
/critic example.com
```

### Agents -- cloud Grok (example)

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

### Agents -- cloud Claude (example)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python recon_agents.py config set --provider anthropic --model claude-sonnet-4-20250514
python recon_agents.py check-llm
python recon_agents.py run --target example.com --approve
```

Skills (C0-C4 + surface mini-skills) load automatically for either local or cloud.

---

## Safety reminder

- Written authorization before `/scope add`
- Detection + **safe** validation only by default
- Secrets stay in `~/.reconkit/secrets.env`
- Treat `~/.reconkit/output` as sensitive

Happy (authorized) hunting.
