# reconkit v3.0.0 â€” Complete Usage Guide

Cross-platform (Windows / Linux / macOS) toolkit for **authorized** bug bounty
recon, **program-weighted scoring**, **safe prove**, an **attack-path graph**,
**multi-provider LLMs** (Ollama + Grok/Claude/Gemini/…), and a **role-routed
agent skill suite** (C0–C4 FP reduction). It does **not** run exploit frameworks
(sqlmap, shells, dumps).

> **v3.0.0** folder = project root for these features (older releases remain available separately).

| Document | Purpose |
|----------|---------|
| **[USAGE.md](USAGE.md)** (this file) | Architecture, modules, configs, dashboard, troubleshooting |
| **[OPERATIONS.md](OPERATIONS.md)** | **Every operation** with CLI + shell + API examples |
| **[WORKFLOW.md](WORKFLOW.md)** | Ordered hunt phases with copy-paste examples |
| **[AGENTS.md](AGENTS.md)** | LLM / skills / program / prove / graph quick start |
| **[skills/README.md](skills/README.md)** | Agent skill suite overview |
| **[skills/SKILLS_INDEX.md](skills/SKILLS_INDEX.md)** | C0–C4 + on-demand mini-skills |
| **[ROADMAP.md](ROADMAP.md)** | v3.0 status + future ideas |

> Use folder **`the Reconkit project root`** as the project root. Older trees (`v2.1.0`,
> `v2.0.1`, `v2.0`) stay unchanged.

**Need a command example right now?** → **[OPERATIONS.md](OPERATIONS.md)**  
**Need a full hunt script?** → **[WORKFLOW.md](WORKFLOW.md)**

---

## Table of contents

1. [What you get](#1-what-you-get)
2. [Project layout](#2-project-layout)
3. [Local data layout (`~/.reconkit`)](#3-local-data-layout-reconkit)
4. [Entry points (how to launch)](#4-entry-points-how-to-launch)
5. [One-time setup](#5-one-time-setup)
6. [Authorization (scope gate)](#6-authorization-scope-gate)
7. [API keys](#7-api-keys)
8. [Recon modules](#8-recon-modules)
9. [Running recon (`reconkit.py`)](#9-running-recon-reconkitpy)
10. [Verbosity & debug levels](#10-verbosity--debug-levels)
11. [Interactive cyber shell](#11-interactive-cyber-shell)
12. [Findings index (not a DB)](#12-findings-index-not-a-db)
13. [Cyber dashboard (web UI)](#13-cyber-dashboard-web-ui)
14. [Multi-agent recon](#14-multi-agent-recon)
15. [Configuration reference (all configs)](#15-configuration-reference-all-configs)
16. [LLM / agent config (usage)](#16-llm--agent-config-usage)
17. [VM → Windows Ollama](#17-vm--windows-ollama)
18. [Upgrades Tier A–D](#18-upgrades-tier-ad-scoring-diff-report-jobs-agents)
19. [Prove / safe validation](#19-prove--safe-validation-v21)
20. [Program profiles & graph (v3.0)](#20-program-profiles--graph-v30)
21. [Agent skill suite](#21-agent-skill-suite)
22. [Feature matrix](#22-feature-matrix-everything-available)
23. [Output files cheat sheet](#23-output-files-cheat-sheet)
24. [Quick reference](#24-quick-reference-all-clis)
25. [Safety & ethics](#25-safety--ethics)
26. [Troubleshooting](#26-troubleshooting)
27. [Complete operations index](#27-complete-operations-index)
28. [Hunter extras](#28-hunter-extras)

---

## 1. What you get

Six layers, one toolkit:

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Cyber shell (recon_shell.py)  Â·  slash commands  Â·  colors â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  reconkit pipeline   Â·  modules  Â·  scope  Â·  keys  Â·  setupâ”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  prove (safe validation)  Â·  queue from index  Â·  canaries  â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  recon-agents  Â·  Ollama + cloud LLMs  Â·  skill suite C0–C4 â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  findings index + program weights  Â·  attack graph           â”‚
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚  dashboard UI  Â·  Recon / Proofs / Graph / Insights         â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

| Layer | Role |
|-------|------|
| **reconkit** | Install tools, enforce scope, run scan modules, write files |
| **prove** | Safe re-check of candidates (markers/canaries only) |
| **agents** | LLM chooses next modules; local **or** cloud providers; skills |
| **skills** | Role-routed + on-demand mini-skills; FP kill + prove mapping |
| **findings / graph / programs** | Index, scores, attack paths, BB weights |
| **dashboard** | Local cyber web UI (typography + evidence console) |
| **shell** | One interactive place to drive everything |

---

## 2. Project layout

```
v3.0.0/                          # â† cd here for all commands
â”œâ”€â”€ USAGE.md                     # this reference
â”œâ”€â”€ WORKFLOW.md                  # ordered hunt + examples
â”œâ”€â”€ OPERATIONS.md                # every CLI/shell/API operation
â”œâ”€â”€ HUNTER.md                    # hunter extras (session, HAR, inbox, extra modules)
â”œâ”€â”€ AGENTS.md
â”œâ”€â”€ ROADMAP.md
â”œâ”€â”€ reconkit.py                  # pipeline + setup + scope + prove CLI
â”œâ”€â”€ recon_shell.py               # interactive cyber prompt
â”œâ”€â”€ recon_dashboard.py           # web UI (Scan/Findings/Inbox/Proofs/Graph/Insights)
â”œâ”€â”€ hunter/                      # session, extra stages, HAR, evidence, inbox
â”œâ”€â”€ recon_agents.py              # multi-agent CLI (local + cloud)
â”œâ”€â”€ recon_prove.py               # safe validation CLI
â”œâ”€â”€ prove/                       # queue, validators, policy, store
â”œâ”€â”€ programs/                    # BB program profile loader
â”œâ”€â”€ graph/                       # attack-path graph builder
â”œâ”€â”€ shell/                       # REPL, theme, slash commands
â”œâ”€â”€ findings/                    # indexer + scoring + store
â”œâ”€â”€ dashboard/                   # HTTP server + static UI
â”‚   â””â”€â”€ static/                  # app.css (Helvetica/Inter + JetBrains Mono)
â”œâ”€â”€ agents/
â”‚   â”œâ”€â”€ llm.py                   # multi-provider client
â”‚   â”œâ”€â”€ skills.py                # role + surface skill injection
â”‚   â””â”€â”€ eval.py                  # zero-token C0–C4 pre-eval
â”œâ”€â”€ skills/                      # Agent Skills suite (SKILL.md packs)
â”‚   â”œâ”€â”€ README.md
â”‚   â”œâ”€â”€ SKILLS_INDEX.md
â”‚   â”œâ”€â”€ reconkit-bug-bounty/
â”‚   â”œâ”€â”€ reconkit-efficiency/
â”‚   â”œâ”€â”€ reconkit-fp-eval/
â”‚   â”œâ”€â”€ reconkit-exploit-prove/
â”‚   â”œâ”€â”€ reconkit-triage-gate/
â”‚   â””â”€â”€ reconkit-vuln-*/         # on-demand mini-skills
â”œâ”€â”€ playbooks.py
â”œâ”€â”€ plugins/
â””â”€â”€ config/
    â”œâ”€â”€ agent_config.json
    â”œâ”€â”€ agent_config.vm-example.json
    â”œâ”€â”€ agent_config.cloud-examples.json
    â”œâ”€â”€ agent.env.example
    â”œâ”€â”€ exploit_policy.json
    â””â”€â”€ programs/                # default.json, example-web.json
```

---

## 3. Local data layout (`~/.reconkit`)

Runtime data is **outside the repo** so you never commit secrets or scan loot.

```
~/.reconkit/   (Windows: C:\Users\<you>\.reconkit\)
â”œâ”€â”€ config.json              # reconkit settings
â”œâ”€â”€ scope.txt                # authorized targets (hard gate)
â”œâ”€â”€ secrets.env              # API keys (owner-only; never commit)
â”œâ”€â”€ session.json             # optional auth cookies/headers (chmod 600; never commit)
â”œâ”€â”€ agent_config.json        # optional user-global LLM config
â”œâ”€â”€ wordlists/               # SecLists, OneListForAll, resolvers
â”œâ”€â”€ logs/
â”‚   â””â”€â”€ debug.log            # tool stderr every run (always)
â”œâ”€â”€ index/
â”‚   â””â”€â”€ findings_index.json  # scored recon records + fingerprint
â”œâ”€â”€ history/
â”‚   â””â”€â”€ <target>/            # reindex snapshots for /diff
â”œâ”€â”€ notes/                   # optional personal notes for /tips
â””â”€â”€ output/
    â””â”€â”€ <target>/            # one folder per scanned domain
        â”œâ”€â”€ subdomains.txt
        â”œâ”€â”€ alive.txt
        â”œâ”€â”€ urls.txt
        â”œâ”€â”€ …
        â”œâ”€â”€ agent_state.json
        â”œâ”€â”€ agent_report.md      # /agent
        â”œâ”€â”€ report_draft.md      # /report (+ proofs section)
        â”œâ”€â”€ critic_review.md     # /critic
        â””â”€â”€ proofs/              # /prove results (v2.1)
            â”œâ”€â”€ proofs_index.json
            â””â”€â”€ <proof_id>.json
```

**Mental model:** files under `output/` are the source of truth.  
`findings_index.json` is a **query cache** for the UI â€” not a separate database of live assets.

Also installed outside `~/.reconkit` when you run `setup`:

| What | Where |
|------|--------|
| Go tools (subfinder, httpx, nuclei, …) | `~/go/bin/` |
| Rust tools (feroxbuster, findomain, …) | `~/.cargo/bin/` |
| Python tools (arjun, uro, …) | user site-packages + Scripts |
| gf patterns | `~/.gf/` |
| Nuclei templates | `~/nuclei-templates/` |

---

## 4. Entry points (how to launch)

Always run from the **v2.0.1** directory (or put it on `PYTHONPATH`).

| Launcher | Use when |
|----------|----------|
| `python recon_shell.py` | **Recommended daily driver** â€” interactive cyber prompt + live `/` matches |
| `python reconkit.py …` | Scripts, CI, one-shot commands (+ `prove …`) |
| `python recon_prove.py …` | Safe validation queue/run (prove layer) |
| `python recon_agents.py …` | Multi-agent LLM recon / `check-llm` / `config` |
| `python recon_dashboard.py` | Browse findings in the browser |
| `python -m agents …` | Same as `recon_agents.py` |
| `python -m shell` | Same as `recon_shell.py` |

Windows examples use `python`; Linux/macOS may use `python3`.  
Shell LIVE autocomplete needs: `pip install prompt_toolkit` (see Â§11a).

---

## 5. One-time setup

### 5.1 Prerequisites on PATH

- Python 3.10+ (3.11+ recommended)
- `git`
- `go` (for ProjectDiscovery / tomnomnom tools)
- `cargo` optional (Rust tools)
- Internet for first install / wordlists
- **`prompt_toolkit`** (recommended) â€” live slash autocomplete in the shell  
  `pip install prompt_toolkit`
- **`colorama`** (optional on Windows) â€” colors in older consoles

### 5.2 Install sequence

```bash
cd path/to/v2.1.0

pip install prompt_toolkit colorama   # shell UX (LIVE autocomplete + colors)
python reconkit.py checkenv           # OS, tools, key visibility
python reconkit.py setup              # install tools, gf, nuclei templates, config
# Apply PATH lines that setup prints, then new terminal
python reconkit.py verify             # confirm binaries resolve
python reconkit.py wordlists          # SecLists, OneListForAll, resolvers
```

`setup` is **idempotent** â€” safe to re-run; skips what already exists.

### 5.3 PATH (one-time, for *your* shell)

`reconkit` injects Go/Cargo/user-script dirs for **its** subprocesses.  
To run `subfinder` yourself in a terminal, permanently add those dirs:

- **Linux:** `~/.bashrc`
- **macOS:** `~/.zshrc`
- **Windows:** `setx` / user environment variables

### Shell equivalents

```text
/checkenv
/setup
/verify
/wordlists
```

---

## 6. Authorization (scope gate)

**Nothing in `run` / `/run` / agents executes** against a host that is not in scope.

```bash
python reconkit.py scope add example.com          # type yes to confirm authorization
python reconkit.py scope add "*.example.com"      # wildcard OK
python reconkit.py scope list
python reconkit.py scope check example.com
```

File: `~/.reconkit/scope.txt` (one domain per line, `#` comments allowed).

### Shell

```text
/scope add example.com
/scope list
/scope check example.com
```

---

## 7. API keys

Optional but critical for **subdomain yield** (`subfinder -all`, chaos, GitHub, …).

```bash
python reconkit.py keys set PDCP_API_KEY <value>       # chaos / ProjectDiscovery
python reconkit.py keys set GITHUB_TOKEN <value>
python reconkit.py keys set SHODAN_API_KEY <value>
python reconkit.py keys set CENSYS_API_ID <value>      # + CENSYS_API_SECRET
python reconkit.py keys set SECURITYTRAILS_API_KEY <value>
python reconkit.py keys set VIRUSTOTAL_API_KEY <value>

python reconkit.py keys list                           # values masked
python reconkit.py keys remove SHODAN_API_KEY
```

Storage: `~/.reconkit/secrets.env` (chmod 600 on Unix). **Never commit this file.**  
Loaded automatically into the process env on every run.

### Shell

```text
/keys list
/keys set PDCP_API_KEY <value>
/keys remove PDCP_API_KEY
```

---

## 8. Recon modules

List anytime:

```bash
python reconkit.py modules
# shell: /modules
# agents: python recon_agents.py modules
```

| Module | What it does |
|--------|----------------|
| `subdomains` | subfinder, amass, assetfinder, chaos, findomain, crt.sh, Wayback, HackerTarget → merge/dedupe |
| `permute` | Capped DNS permutations (alterx/dnsgen) then dnsx |
| `dns` | dnsx multi-record + CNAME takeover fingerprint candidates |
| `ports` | In-scope naabu connect-scan of common web/data ports + httpx |
| `httpprobe` | httpx alive hosts, title, status, tech (session headers; WAF → stealth) |
| `tls` | tlsx cert details, expiry/self-signed/mismatch, JARM |
| `wellknown` | robots.txt, sitemap, security.txt, OpenID, assetlinks |
| `crawl` | katana, gospider, hakrawler, gau, waybackurls → **in-scope URLs only** |
| `js` | collect `.js`, regex extract secrets/endpoints (read-only) |
| `jsintel` | sourcemaps, hidden routes, API paths, JS library versions, GitHub URLs |
| `params` | unfurl param names + arjun hidden params |
| `apis` | `/api/` `/graphql` `/swagger` harvest + IDOR-shaped parameter URLs |
| `content` | sensitive paths + ffuf directory fuzz |
| `bypass403` | header/path 401/403 probes (**no** password spray) |
| `gfextra` | gf redirect / lfi / interestingparams candidate lists |
| `xss` | gf xss → kxss → dalfox (**detection** of candidates) |
| `sqli` | gf sqli → error/boolean **detection canaries** (non-destructive) |
| `ssrf_ssti` | cloud-metadata SSRF probe + `{{7*7}}` SSTI canary |
| `redirect` | open-redirect canary (OAST or `.invalid` bounce) |
| `cors` | CORS ACAO reflection with Origin canary |
| `graphql` | GraphQL `{__typename}` detect (no schema dump) |
| `nuclei` | CVE / takeover / panel / misconfig + tech-tagged templates |
| `cloud` | S3/Azure/GCP/Firebase refs + read-only S3 public list check |
| `takeover_plus` | package.json / dangling JS CDN 404s (no auto-claim) |
| `osint` | Shodan/Censys queries constrained to **this hostname** |
| `gitrecon` | GitHub/GitLab URL harvest + optional trufflehog on one public repo |
| `screenshots` | gowitness screenshots of alive hosts |

**Dependency order (logical):**

```
subdomains → permute → dns / ports / httpprobe → tls, wellknown, crawl, content, nuclei, screenshots
crawl → js → jsintel, params, apis, gfextra, xss, sqli, ssrf_ssti, redirect, cors, graphql, cloud, takeover_plus, gitrecon
```

Hunter extras walkthrough: **[HUNTER.md](HUNTER.md)**.

Missing tools print `[WARN]` and skip that stage â€” they do not crash the whole run.

---

## 9. Running recon (`reconkit.py`)

### Full or partial pipeline

```bash
# Full pipeline (all modules)
python reconkit.py run --target example.com

# Selected modules (comma-separated, no spaces)
python reconkit.py run --target example.com --modules subdomains,dns,httpprobe,nuclei

# With verbosity (flags BEFORE subcommand)
python reconkit.py --debug run --target example.com
python reconkit.py -v 3 run --target example.com --modules subdomains
python reconkit.py run --target example.com --resume
python reconkit.py run --scope-all --modules subdomains,dns,httpprobe
```

Output: `~/.reconkit/output/example.com/`

### Shell shortcuts

```text
/target example.com
/run example.com
/run example.com --modules subdomains,dns,httpprobe
/run example.com --resume
/run --scope-all --modules subdomains,dns,httpprobe
/quick example.com          # subdomains + dns + httpprobe
/full example.com           # all modules
/scan                       # interactive module picker (toggle numbers, Enter to run)
/session set --cookie "sid=…"
/inbox example.com
```

### Interactive `/scan` picker

1. Lists every module with `[x]` / `[ ]`
2. Type numbers to toggle, or `a`=all, `n`=none, `d`=defaults  
3. `Enter` / `r` = run Â· `q` = cancel  

---

## 10. Verbosity & debug levels

Global flags must come **before** the subcommand:

```bash
python reconkit.py -v LEVEL <command> …
python reconkit.py --debug <command> …     # same as -v 2
```

| Level | Name | Console behavior |
|------:|------|------------------|
| **0** | quiet | Banners + OK/WARN/FAIL mainly |
| **1** | normal | Default â€” `$ command` lines + stage progress |
| **2** | debug | + timing, exit codes, stderr snippets, stage file diffs |
| **3** | **live** | + full live stdout/stderr streams of tools |

Shell:

```text
/verbose
/verbose 2
/verbose live
/verbose debug
```

Agents:

```bash
python recon_agents.py run --target example.com --debug
python recon_agents.py run --target example.com -v 3
```

**Always logged** (even without debug): `~/.reconkit/logs/debug.log`

---

## 11. Interactive cyber shell

### Start

```bash
python recon_shell.py
python recon_shell.py --target example.com -v 2
python reconkit.py shell --target example.com
```

### Prompt

Single-line prompt (so the live match strip can sit **above** it):

```text
  /commands  /config
  List every slash command …  Â· Tab complete Â· Enter run
reconkit@v2.1.0 [target:example.com] [v:1:normal] â–¸ /co
```

| Field | Meaning |
|-------|---------|
| `target:…` | Session target from `/target` (or `none`) |
| `v:N:label` | Verbosity 0–3 (`quiet` / `normal` / `debug` / `live`) |

### 11a. Live autocomplete + slash menu (like Grok Build CLI)

#### Live matches while typing (main feature)

Requires **`prompt_toolkit`** and a real terminal (Windows Terminal, cmd.exe,
or a normal Linux TTY â€” not a bare IDE â€œOutputâ€ panel).

```bash
pip install prompt_toolkit
python recon_shell.py
```

On startup you should see:

```text
  Autocomplete: LIVE âœ“
    Matches appear above the prompt as you type
    Type / → all commands
    Keep typing /co → /commands  /config
    Type /comm → /commands   then Enter to run
    Keys: Tab complete Â· Enter run Â· Ctrl-Space force menu
```

**How filtering works**

| You type | Matches drawn **above** the prompt |
|----------|--------------------------------------|
| `/` | First commands (+ â€œ+N moreâ€) |
| `/c` | `/commands`, `/clear`, `/config`, … |
| `/co` | `/commands`  `/config` |
| `/comm` | `/commands` only |
| `/scope ` (trailing space) | subcommands `add`  `list`  `check` |
| `/scope a` | `add` |
| `/run T --modules ` | **module values**: `subdomains` `dns` `httpprobe` … `all` |
| `/run T --modules subdomains,` | remaining modules as CSV |
| `/keys set ` | known API key names |
| `/config set --provider ` | `ollama` `xai` `anthropic` `openai` … |
| `/prove run T --technique ` | safe validators (`xss_reflect`, …) |
| `/playbook run ` | playbook names |
| `/program set ` | program profile names |

Value catalogs live in `shell/suggestions.py` (contextual engine).

**Keys**

| Key | Action |
|-----|--------|
| **Tab** | Complete / cycle completions |
| **Enter** | If prefix is unique → expand + run (e.g. `/comm` → `/commands`). Ambiguous prefixes open the numbered picker or print matches |
| **Ctrl-Space** | Force the floating completion menu |
| **â†‘** (history) | Previous lines from `~/.reconkit/shell_history.txt` |

Example while typing `/comm`:

```text
  /commands
  List every slash command (same as typing /)  Â· Tab complete Â· Enter run
reconkit@v2.1.0 [target:none] [v:1:normal] â–¸ /commâ–ˆ
```

A second strip may also appear at the **bottom of the terminal** (bottom toolbar).

If startup says `Autocomplete: OFF (…)`, install `prompt_toolkit`, use a real
console, and restart the shell.

#### Full interactive menu (pick by number)

Type **`/`** alone + **Enter** (nothing after the slash):

```text
â–¸ /
```

Numbered list of **all main commands and subcommands**. At `/filterâ–¸`:

| Input | Effect |
|-------|--------|
| empty / `q` | Close |
| `scope` | Filter rows |
| `2` | Run row #2 in the filtered list |
| `?run` | `/help run` |
| pick `/scope add` | Prompt for domain |

Also: `/sco` opens filtered menu; `/commands` opens full menu.

### 11b. Inline help on **every** shell command (`-h` / `--help`)

This is a **global** shell feature: the dispatcher intercepts help flags for
**all** registered commands (setup, scope, keys, run, scan, agent, dashboard,
findings, config, …) â€” not only `/agents`.

You should rarely need external docs during a hunt. Discover usage in-shell:

```text
/<any-command> -h
/<any-command> --help
/<any-command> -?
/<any-command> /?
/<any-command> help
```

| Flag | Works on | Example |
|------|----------|---------|
| `-h` | **all** commands | `/run -h` Â· `/scope -h` Â· `/keys -h` Â· `/agent -h` |
| `--help` | **all** commands | `/dashboard --help` Â· `/findings --help` |
| `-?` / `/?` | **all** commands | `/verbose -?` Â· `/modules /?` |
| bare `help` | **all** commands | `/config help` Â· `/check-llm help` |

Also:

| Form | Example |
|------|---------|
| Full catalog | `/help` |
| One command via help | `/help run` Â· `/help scope` |
| Names + `-h` hints | `/` or `/commands` (lists every cmd with a `-h` reminder) |

**Complete set of commands that accept `-h`** (same as `/` list):

```text
/help  /commands  /banner  /clear  /status  /verbose  /target  /exit
/checkenv  /setup  /verify  /wordlists
/scope  /keys
/modules  /scan  /run  /quick  /full  /outdir  /findings  /dashboard
/agents  /agent  /check-llm  /config
```

**What each `-h` screen includes**

| Field | Meaning |
|-------|---------|
| `usage` | Exact invocation pattern |
| `about` | One-line summary |
| `category` | shell / setup / auth / recon / agents |
| `aliases` | Other names (`/t` → target, `/dash` → dashboard, …) |
| `help via` | All help spellings for this command |
| `min/max args` | When present |
| `details` | Full prose: subcommands, flags, examples, CLI equivalent |

**Sample drill (learn without docs)**

```text
â–¸ /                    # see every command + â€œcmd -hâ€ hints
â–¸ /setup -h            # how to install tools
â–¸ /scope -h            # authorize targets
â–¸ /keys --help         # API keys
â–¸ /modules -h          # recon stages
â–¸ /run -h              # pipeline flags
â–¸ /scan --help         # interactive picker
â–¸ /quick -h
â–¸ /full -h
â–¸ /verbose -h          # 0–3 levels
â–¸ /findings -h         # index for UI
â–¸ /dashboard --help    # web UI
â–¸ /agents -h           # list specialists (no scan)
â–¸ /agent -h            # LLM loop (this contacts the model)
â–¸ /check-llm help
â–¸ /config -h
â–¸ /outdir -h
â–¸ /status -h
â–¸ /exit -h
```

Wrong arity points at help for **that** command:

```text
â–¸ /scope
[FAIL] scope: need at least 1 argument(s)
  usage: /scope <add|list|check> [domain]
  tip:   /scope -h   for full help

â–¸ /keys
[FAIL] keys: need at least 1 argument(s)
  tip:   /keys -h   for full help

â–¸ /config
  tip:   /config -h   for full help
```

Help is handled **before** required-argument checks, so `/scope -h` and
`/config --help` always work even when the command normally needs subcommands.

**Aliases work too:** `/dash -h`, `/t --help`, `/wl -h`, `/recon -h`, `/llm -h`.

### Slash commands (complete list)

Type **`/`** alone to list names. Type **`/help`** for the full catalog.  
Any command: **`/<cmd> -h`**. Bare names work too (`help`, `run`, …).  
Tab-completes slash names when readline is available.

#### Shell & session

| Command | Usage | Purpose |
|---------|--------|---------|
| `/help` | `/help [cmd]` | Catalog or one-command help |
| *any* | `/<cmd> -h` Â· `--help` Â· `-?` Â· `help` | **Inline help for that command** |
| `/commands` | `/commands` | Same as typing `/` |
| `/banner` | `/banner` | Redraw banner |
| `/clear` | `/clear` | Clear terminal |
| `/status` | `/status` | Target, verbose, scope, paths, LLM |
| `/verbose` | `/verbose <0-3\|name>` | Set verbosity |
| `/target` | `/target [domain]` | Set/show session target |
| `/exit` | `/exit` | Quit (`/quit`, `/q`) |

#### Environment & install

| Command | Purpose |
|---------|---------|
| `/checkenv` | Prerequisites + key visibility |
| `/setup` | Install tools (idempotent) |
| `/verify` | PATH tool check |
| `/wordlists` | Download wordlists |

#### Authorization & secrets

| Command | Usage |
|---------|--------|
| `/scope` | `/scope add\|list\|check [domain]` |
| `/keys` | `/keys set\|list\|remove …` |
| `/session` | `/session show\|set\|clear` — cookies/headers for authenticated recon |

#### Recon pipeline

| Command | Usage | Purpose |
|---------|--------|---------|
| `/modules` | | List modules |
| `/scan` | `/scan [target]` | Module picker |
| `/run` | `/run [t] [--modules a,b\|all] [--resume] [--scope-all]` | Pipeline |
| `/quick` | `/quick [target]` | Fast trio |
| `/full` | `/full [target]` | All modules |
| `/har` | `/har import <file.har> [t]` | Import in-scope URLs + Cookie |
| `/inbox` | `/inbox [target]` | C1+ hunter triage queue |
| `/evidence` | `/evidence [t] [--id ID]` | Zip output + proofs |
| `/wordlist-target` | `/wordlist-target [t]` | Target-specific wordlist |
| `/outdir` | `/outdir [target]` | List result files |
| `/findings` | `/findings [reindex\|summary] [t]` | Index |
| `/dashboard` | `/dashboard [--port N] [--no-browser]` | Web UI |

#### Multi-agent LLM

| Command | Usage |
|---------|--------|
| `/agents` | List specialists + skill suite wiring |
| `/agent` | `/agent [t] [--modules a,b] [--dry-run] [--max-steps N] [--approve]` |
| `/check-llm` | Ping LLM (Ollama or cloud) |
| `/config` | `/config show\|path\|init\|set --provider … --model …` |
| CLI only | `python recon_agents.py providers` â€” list local + cloud providers |

Skills inject automatically (see Â§21). Cloud: set API key env, then `/config set --provider xai|anthropic|…`.

---

## 12. Findings index (not a DB)

1. Scans write files → `~/.reconkit/output/<target>/`
2. Reindex **parses** those files → `~/.reconkit/index/findings_index.json`
3. Dashboard/API read the index

```bash
python reconkit.py findings reindex
python reconkit.py findings summary
python reconkit.py findings summary example.com

# shell
/findings reindex
/findings
/findings summary example.com
```

Each finding has roughly: `id`, `target`, `module`, `ftype`, `title`, `asset`,
`severity`, `evidence`, `source_file`, `tags`.

**After new scans:** with **LIVE ON** (default), the UI polls disk and
auto-reloads when `~/.reconkit/output` changes. You can also press **REINDEX**
or run `/findings reindex` â€” **no need to stop/restart the dashboard server**.

---

## 13. Cyber dashboard (web UI)

```bash
python recon_dashboard.py
python recon_dashboard.py --port 8787 --no-browser
python reconkit.py dashboard --host 127.0.0.1 --port 8787
python reconkit.py dashboard --host 0.0.0.0 --port 8787   # VM / LAN

# shell (blocks until Ctrl+C)
/dashboard
/dashboard --port 9000 --no-browser
/dashboard --host 127.0.0.1    # localhost only
```

**Bind default: `127.0.0.1`** (localhost only). Use `--host 0.0.0.0` when the
dashboard runs in a **VM** and you browse from the **Windows host**.

| Where you browse | URL |
|------------------|-----|
| Same machine as the server | http://127.0.0.1:8787/ |
| Windows host → dashboard in VM | http://`<VM_LAN_IP>`:8787/ |

Startup prints guessed LAN IPs. On the VM, allow TCP **8787** in the firewall
if the host cannot connect.

| UI area | What you do |
|---------|-------------|
| **Scan / Findings / Proofs / Graph / Insights** | Live modules, findings (C1+), proofs, attack-path graph, charts |
| Targets | Click one target or ALL (applies to all tabs) |
| KPIs (Recon) | Records, targets, critical / high / medium, proof count |
| KPIs (Proofs) | Total, confirmed, needs_manual, not_exploitable, errors |
| Filters | Module/severity/type (recon) or status/technique (proofs) |
| Tables | Recon results **or** validation proofs |
| Detail | Evidence + impact notes (proofs) or source preview (recon) |
| **Live** | Auto-poll disk (~4s); reloads when scans/proofs write new files |
| **Reindex** | Force re-parse output **without restarting the server** |
| **program:** badge | Active BB scoring profile |

### Typography & evidence console

| Surface | Style |
|---------|--------|
| **UI text** | `Helvetica Neue`, **Inter**, system UI sans-serif |
| **Console / evidence / mono** | **JetBrains Mono** (loaded from Google Fonts) |
| **Evidence / file preview boxes** | Solid background `#1a1d24`, muted text `#a8b0bd` |

This replaces neon green-on-black â€œterminalâ€ styling with a readable solid console.
Open any recon **source preview** or proof **evidence** panel to see it.

Hard-refresh the browser (`Ctrl+F5`) after upgrading so `app.css?v=8` / `app.js?v=8` cache clears.

### API (for scripting)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | Liveness |
| GET | `/api/status` | Disk fingerprint + `proof_count` for live poll |
| GET | `/api/overview` | Recon counts + `proof_count` / `proof_confirmed` |
| GET | `/api/targets` | Target summaries |
| GET | `/api/records?…` | Filtered recon records (preferred) |
| GET | `/api/findings?…` | Same as records (compat alias) |
| GET | `/api/proofs?…` | Filtered proofs (`target`, `status`, `technique`, `q`) |
| GET | `/api/proofs/overview` | Proof KPIs by status/technique |
| GET | `/api/proofs/<target>/<id>` | One proof JSON |
| GET | `/api/graph?target=&min_score=` | Attack-path nodes/edges (findings + proofs) |
| GET | `/api/stats/charts?target=` | Severity/module/score/proof bar-chart data |
| GET | `/api/program` | Active BB program profile + list |
| GET | `/api/file?target=&path=` | Text preview of output file |
| GET | `/api/inbox?target=` | Hunter C1+ triage queue + suggested prove technique |
| POST | `/api/reindex` | Force full rebuild from disk (no process restart) |

### Program profiles & Graph (v3.0)

```bash
# weights affect /notable and prove queue after reindex
# shell:
/program list
/program set example-web
/findings reindex
/graph summary
/graph show example.com

# OAST SSRF (optional): edit config/exploit_policy.json
#   "oast_base_url": "https://YOUR.oast.fun"
# SQLi boolean canary (optional, off by default):
#   "allow_sqli_boolean": true
```

Dashboard tabs: **Scan** · **Findings** (C1+ by default) · **Inbox** · **Proofs** · **Graph** · **Insights**.

**Security:** default bind is **`127.0.0.1`**. `--host 0.0.0.0` is LAN/VM access —
any machine that can reach that IP on port 8787 can see recon data and start
scoped scans. Restrict with the host/VM firewall. Do **not** port-forward this
UI to the public internet.

---

## 14. Multi-agent recon

Instead of a fixed module list, a **planner** LLM picks the next specialist;
specialists run reconkit stages; an **analyst** writes a markdown report.
The same client talks to **local Ollama** or **cloud** APIs (Grok, Claude,
Gemini, OpenAI, …). **Skills** inject methodology by role + vuln surface.

### Specialist map

| Agent | Modules |
|-------|---------|
| `subdomain` | `subdomains` |
| `discovery` | `dns`, `httpprobe`, `tls` |
| `content` | `crawl`, `js`, `params`, `content` |
| `vuln` | `xss`, `sqli`, `ssrf_ssti`, `nuclei`, `cloud` |
| `visual` | `screenshots` |
| `planner` | decides next step (no tools) |
| `analyst` | final `agent_report.md` |

If the LLM is down, **heuristics** still advance the pipeline.

### Providers (list)

```bash
python recon_agents.py providers
```

| provider | Default model | Key env |
|----------|---------------|---------|
| `ollama` | `qwen3:8b` | â€” |
| `xai` / `grok` | `grok-2-latest` | `XAI_API_KEY` |
| `anthropic` / `claude` | `claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` |
| `openai` | `gpt-4o-mini` | `OPENAI_API_KEY` |
| `google` / `gemini` / `gemma` | `gemini-2.0-flash` / `gemma-3-27b-it` | `GOOGLE_API_KEY` |
| `openrouter` | (many) | `OPENROUTER_API_KEY` |
| `groq` | `llama-3.3-70b-versatile` | `GROQ_API_KEY` |
| `deepseek` / `together` / `mistral` / `fireworks` | see `providers` | matching `*_API_KEY` |
| `custom` | you set | `RECON_LLM_API_KEY` |

**Cloud setup docs & configs**

| File | Use |
|------|-----|
| **[config/CLOUD_LLM_SETUP.md](config/CLOUD_LLM_SETUP.md)** | Full cloud walkthrough (PowerShell + bash) |
| `config/agent_config.cloud-example.json` | Drop-in full config (Grok example) |
| `config/agent_config.cloud-presets.json` | Every providerâ€™s `llm` block + setup commands |
| `config/agent_config.cloud-examples.json` | Short snippet catalog |
| `config/agent.env.example` | Env var checklist |

```powershell
# Cloud quickstart (Grok) â€” Windows
$env:XAI_API_KEY = "xai-..."
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py check-llm
# or: copy config\agent_config.cloud-example.json config\agent_config.json
```

### CLI

```bash
python recon_agents.py providers
python recon_agents.py agents          # specialists + skill suite wiring
python recon_agents.py modules
python recon_agents.py config show
python recon_agents.py check-llm

python recon_agents.py run --target example.com --dry-run
python recon_agents.py run --target example.com
python recon_agents.py run --target example.com \
  --modules subdomains,dns,httpprobe,crawl,nuclei --max-steps 6
python recon_agents.py run --target example.com -v 3

# Cloud one-shot (env key must already be set)
python recon_agents.py run --target example.com --provider xai --model grok-2-latest
python recon_agents.py run --target example.com --provider anthropic
```

### Shell

```text
/agents
/check-llm
/config set --provider xai --model grok-2-latest
/agent example.com --dry-run
/agent example.com
/agent example.com --modules subdomains,dns,httpprobe --max-steps 6
```

### Cloud setup examples

```bash
# Grok
export XAI_API_KEY=xai-...
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py check-llm

# Claude
export ANTHROPIC_API_KEY=sk-ant-...
python recon_agents.py config set --provider anthropic --model claude-sonnet-4-20250514
python recon_agents.py check-llm

# Gemini
export GOOGLE_API_KEY=...
python recon_agents.py config set --provider google --model gemini-2.0-flash
python recon_agents.py check-llm
```

Artifacts:

- `~/.reconkit/output/<target>/agent_state.json` â€” resume-friendly memory  
- `~/.reconkit/output/<target>/agent_report.md` â€” analyst summary (skills + pre-eval applied)  

Skills detail: **[Â§21](#21-agent-skill-suite)** Â· full catalog: **OPERATIONS.md Â§13–14**.

---

## 15. Configuration reference (all configs)

v3.0.0 uses **several config surfaces**. None of them require inventing new
syntax in the shell â€” CLI and shell use the same **`--flag value`** style.

### 15.1 Where every setting lives

| Config | Path | Purpose | Edited by |
|--------|------|---------|-----------|
| **Agent LLM config** (primary) | `config/agent_config.json` (repo) and/or `~/.reconkit/agent_config.json` | Provider, model, base URL, orchestrator | `/config set`, `recon_agents.py config …`, hand-edit JSON |
| **Agent VM example** | `config/agent_config.vm-example.json` | Copy-paste template for VM → Windows Ollama | Manual copy → edit |
| **Cloud examples** | `config/agent_config.cloud-examples.json` | Sample `llm` blocks for Grok/Claude/Gemini/… | Copy a block into agent config |
| **Agent env example** | `config/agent.env.example` | Documents env-var overrides + API key names | Copy vars into your shell profile |
| **Exploit / prove policy** | `config/exploit_policy.json` | OAST URL, SQLi boolean allow, risk class | Manual edit |
| **Program profiles** | `config/programs/*.json` | BB category weights | `/program set` |
| **Agent skills** | `skills/*/SKILL.md` | Prompt packs (not secrets) | Env `RECON_AGENT_SKILL*` |
| **reconkit settings** | `~/.reconkit/config.json` | Written by `setup` (paths, install metadata) | `reconkit.py setup` |
| **Scope** | `~/.reconkit/scope.txt` | Authorized targets (hard gate) | `/scope`, `reconkit.py scope` |
| **API secrets** | `~/.reconkit/secrets.env` | Optional recon keys (never commit) | `/keys`, `reconkit.py keys` |
| **Findings index** | `~/.reconkit/index/findings_index.json` | Dashboard cache (auto-built) | `/findings reindex`, dashboard REINDEX |
| **Debug log** | `~/.reconkit/logs/debug.log` | Always-on tool stderr log | automatic |
| **Scan output** | `~/.reconkit/output/<target>/` | Module artifacts | `/run`, agents |

### 15.2 Agent config JSON (`agent_config.json`)

Full schema (defaults shown for local Ollama):

```json
{
  "llm": {
    "provider": "ollama",
    "model": "qwen3:8b",
    "base_url": "http://127.0.0.1:11434",
    "api_key": "",
    "temperature": 0.2,
    "timeout": 300,
    "use_openai_compat": false
  },
  "orchestrator": {
    "max_steps": 12,
    "skip_analyst": false,
    "modules": []
  },
  "network": {
    "notes": "human-readable notes only"
  }
}
```

Cloud example (Grok) â€” copy from `agent_config.cloud-examples.json`:

```json
{
  "llm": {
    "provider": "xai",
    "model": "grok-2-latest",
    "base_url": "https://api.x.ai/v1",
    "api_key": "",
    "timeout": 120
  }
}
```

Prefer env keys (`XAI_API_KEY`, …) over putting secrets in JSON.

#### `llm.*` keys

| JSON key | Type | Default | Meaning |
|----------|------|---------|---------|
| `provider` | string | `ollama` | `ollama` \| `xai` \| `anthropic` \| `openai` \| `google` \| `openrouter` \| `groq` \| `deepseek` \| `together` \| `mistral` \| `fireworks` \| `custom` (aliases: `grok`, `claude`, `gemini`, `gemma`) |
| `model` | string | `qwen3:8b` | Exact model id/tag (must exist on host for Ollama; cloud uses providerâ€™s id) |
| `base_url` | string | `http://127.0.0.1:11434` | **Client** URL. Ollama: host LAN IP from a VM. Cloud: preset when you `config set --provider …` |
| `api_key` | string | `""` | Online providers; prefer env (`XAI_API_KEY`, …). Ollama usually empty |
| `temperature` | float | `0.2` | Sampling temperature |
| `timeout` | int | `300` | HTTP timeout seconds (raise for slow remote qwen3; cloud often 120 is fine) |
| `use_openai_compat` | bool | `false` | Ollama: `false` = native `/api/chat`; `true` = `/v1/chat/completions`. Cloud OpenAI-compat providers set this appropriately |

#### `orchestrator.*` keys

| JSON key | Type | Default | Meaning |
|----------|------|---------|---------|
| `max_steps` | int | `12` | Planner → specialist loop limit |
| `skip_analyst` | bool | `false` | Skip final `agent_report.md` |
| `modules` | string[] | `[]` | Permanent module allowlist; empty = all modules |

#### `network.notes`

Free-text for humans only (shown in diagnostics). Does not change runtime.

### 15.3 Config discovery order (agent)

First **usable** file wins (unless `--config PATH` forces a path):

1. `$RECON_AGENT_CONFIG`  
2. `./config/agent_config.json` (cwd)  
3. `./agent_config.json` (legacy)  
4. `<repo>/config/agent_config.json`  
5. `~/.reconkit/agent_config.json`  

**Usable** means: non-empty file that parses as a JSON object. Empty files,
corrupt JSON, or accidental UTF-16 saves are **skipped** (with a stderr warning)
so `check-llm` does not crash. If the project `config/agent_config.json` itself
is empty/corrupt, agents may **rewrite it from built-in defaults** and continue.

Explicit `--config PATH` still hard-fails with a clear fix hint if that path is
empty or invalid.

See which file is active:

```bash
python recon_agents.py config path
# shell:
/config path
```

Repair examples:

```bash
# rewrite user-global config
python recon_agents.py config init --force --base-url http://192.168.1.4:11434 --model qwen3:8b

# rewrite project config
python recon_agents.py config init --repo --force --base-url http://192.168.1.4:11434 --model qwen3:8b
```

### 15.4 Priority (highest wins)

When agents run (`/agent` or `recon_agents.py run`):

1. **CLI flags** on that run (`--base-url`, `--model`, …)  
2. **Environment variables** (see Â§15.5)  
3. **Config file** (discovered above)  
4. **Built-in defaults** (`ollama` / `qwen3:8b` / `http://127.0.0.1:11434`)  

`/config set` **writes the config file** so future runs pick it up without flags.

### 15.5 Environment variables

Documented in `config/agent.env.example`. Useful overrides:

| Variable | Maps to |
|----------|---------|
| `RECON_AGENT_CONFIG` | Force config file path |
| `RECON_LLM_PROVIDER` | `llm.provider` (`ollama`, `xai`, `anthropic`, `google`, …) |
| `RECON_LLM_MODEL` | `llm.model` |
| `RECON_LLM_BASE_URL` | `llm.base_url` (preferred client URL) |
| `RECON_LLM_API_KEY` | `llm.api_key` (generic / custom) |
| `RECON_LLM_TEMPERATURE` | `llm.temperature` |
| `RECON_LLM_TIMEOUT` | `llm.timeout` |
| `RECON_LLM_OPENAI_COMPAT` | `llm.use_openai_compat` (`true`/`false`) |
| `RECON_MAX_STEPS` | `orchestrator.max_steps` |
| `RECON_AGENT_SKILL` | Primary skill name or `off` |
| `RECON_AGENT_SKILL_EXTRA` | Comma list of skills always merged |
| `RECON_AGENT_SKILL_MAX` | Max chars of skill text injected (default 14000) |
| `RECON_PROGRAM` | Active program profile id |
| `OLLAMA_MODEL` | model alias when using Ollama |
| `OLLAMA_HOST` | If set to a full `http://…` URL, may act as client base; bare `0.0.0.0` is a **server bind** and is **not** used as agent base_url |
| `XAI_API_KEY` / `GROK_API_KEY` | xAI Grok |
| `ANTHROPIC_API_KEY` / `CLAUDE_API_KEY` | Anthropic Claude |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | Google Gemini / Gemma |
| `OPENAI_API_KEY` / `GROQ_API_KEY` / `OPENROUTER_API_KEY` | Online API keys |
| `DEEPSEEK_API_KEY` / `TOGETHER_API_KEY` / `MISTRAL_API_KEY` / `FIREWORKS_API_KEY` | Other OpenAI-compat clouds |
| `OPENAI_MODEL` / `OPENAI_BASE_URL` | Online model / base |

### 15.6 reconkit secrets (`secrets.env`)

| Key | Unlocks / used by |
|-----|-------------------|
| `PDCP_API_KEY` | chaos / ProjectDiscovery Cloud |
| `GITHUB_TOKEN` | github-subdomains + subfinder GitHub source |
| `SHODAN_API_KEY` | Shodan / subfinder source |
| `CENSYS_API_ID` (+ `CENSYS_API_SECRET`) | Censys |
| `SECURITYTRAILS_API_KEY` | subfinder SecurityTrails |
| `VIRUSTOTAL_API_KEY` | subfinder VirusTotal |

```bash
python reconkit.py keys set PDCP_API_KEY <value>
python reconkit.py keys list
# shell:
/keys set PDCP_API_KEY <value>
/keys list
```

### 15.7 Scope file (`scope.txt`)

One domain or wildcard per line; `#` comments allowed.

```text
example.com
*.example.com
# lab only
```

```bash
python reconkit.py scope add example.com   # type yes
/scope add example.com
```

---

## 16. LLM / agent config (usage)

### Important: recon vs agents

| Action | Uses `agent_config.json`? |
|--------|---------------------------|
| `/run`, `/quick`, `/full`, `/scan`, `reconkit.py run` | **No** â€” tools only |
| `/agent`, `recon_agents.py run` | **Yes** â€” planner / specialists / analyst |
| `/check-llm` | **Yes** â€” ping only |
| `/config show\|set` | Reads/writes agent config |

### CLI

```bash
python recon_agents.py providers
python recon_agents.py config show
python recon_agents.py config path
python recon_agents.py config init --repo \
  --base-url http://127.0.0.1:11434 --model qwen3:8b --provider ollama
python recon_agents.py config set --base-url http://192.168.1.4:11434
python recon_agents.py config set --model qwen3:8b --timeout 300
python recon_agents.py config set --provider ollama --base-url http://192.168.1.4:11434
# Cloud: set the provider key in the environment first
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py config set --provider anthropic --model claude-sonnet-4-20250514
python recon_agents.py config set --provider google --model gemini-2.0-flash
python recon_agents.py config set --provider groq --model llama-3.3-70b-versatile

python recon_agents.py check-llm
python recon_agents.py check-llm --provider xai
# Ollama: "Ollama reachable â€” models …" then "OK â€” model replied: pong"
# Cloud:  "OK â€” model replied: pong" (needs API key)
```

`check-llm` loads the discovered config, prints the effective summary, pings the
provider (Ollama `/api/tags` + chat, or cloud chat). On Ollama connection errors
it prints VM → host recovery steps (see Â§17).

### Shell â€” **always use `--flag` form**

```text
/config show
/config path
/config -h

/config init --repo --base-url http://127.0.0.1:11434 --model qwen3:8b

# Correct:
/config set --base-url http://192.168.1.4:11434
/config set --model qwen3:8b --timeout 300
/config set --provider ollama --base-url http://192.168.1.4:11434
/config set --provider xai --model grok-2-latest
/config set --provider anthropic --model claude-sonnet-4-20250514

# Wrong (rejected on purpose â€” avoids ambiguous bare keys):
/config set base_url http://192.168.1.4:11434
```

**Flags for `/config set` / `config set`:**

| Flag | JSON field |
|------|------------|
| `--base-url` | `llm.base_url` |
| `--model` | `llm.model` |
| `--provider` | `llm.provider` |
| `--api-key` | `llm.api_key` |
| `--temperature` | `llm.temperature` |
| `--timeout` | `llm.timeout` |
| `--max-steps` | `orchestrator.max_steps` |
| `--openai-compat true\|false` | `llm.use_openai_compat` |
| `--config PATH` | which file to edit (when supported by CLI) |

**Flags for `/config init`:**

| Flag | Meaning |
|------|---------|
| `--repo` | Write to repo `config/agent_config.json` |
| `--path PATH` | Explicit path |
| `--base-url` | Initial base URL |
| `--model` | Initial model |
| `--provider` | Initial provider |
| `--force` | Overwrite existing file |

Verify after any change:

```text
/config show
/check-llm
```

### Per-run override (does not rewrite the file)

```bash
python recon_agents.py run --target example.com \
  --base-url http://192.168.1.4:11434 --model qwen3:8b

python recon_agents.py run --target example.com \
  --provider xai --model grok-2-latest

python recon_agents.py run --target example.com \
  --provider anthropic --model claude-sonnet-4-20250514
```

For durable defaults in the shell, use `/config set --provider …` / `--base-url …`,
then `/agent example.com`.

---

## 17. VM → Windows Ollama

Typical lab: **Ollama on Windows**, **recon agents on Kali/Linux VM**.

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”  HTTP :11434   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Windows host    â”‚ â—„â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ â”‚  VM (recon agents)      â”‚
â”‚  Ollama+qwen3    â”‚   client URL   â”‚  python recon_agents.py â”‚
â”‚  e.g. 192.168.1.4â”‚                â”‚  e.g. 192.168.20.131    â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

### Critical: which IP goes in `base_url`?

| Value | Put in `llm.base_url`? | Why |
|-------|------------------------|-----|
| **Windows host LAN IP** (where Ollama runs) | **Yes** | Agents must call the host |
| Kali / VM IP | **No** | That is *this* machine â€” Ollama is not listening → `Connection refused` (errno 111) |
| `127.0.0.1` / `localhost` (from the VM) | **No** | Loopback is the VM, not Windows |
| `0.0.0.0` | **No** | Server bind address only â€” not a client URL |

Real lab mistake that fails `check-llm`:

```text
# Wrong â€” this was the Kali IP
base_url: http://192.168.20.131:11434
FAILED (tags): ... Connection refused

# Right â€” Windows host where curl already works
base_url: http://192.168.1.4:11434
```

### 17.1 Windows host (Ollama server)

```text
setx OLLAMA_HOST 0.0.0.0
# Fully quit and restart the Ollama app / service
ollama pull qwen3:8b
# Windows Firewall: allow inbound TCP 11434
# Confirm on Windows:
curl http://127.0.0.1:11434/api/tags
```

`OLLAMA_HOST=0.0.0.0` is the **daemon bind**. Do **not** copy `0.0.0.0` into
`agent_config.json`.

### 17.2 VM (agents client)

1. From the VM, find a working Windows IP:

```bash
# try until you see "Ollama is running" or JSON models list
curl -v http://192.168.1.4:11434/
curl -s http://192.168.1.4:11434/api/tags
```

2. Point agents at that IP (must use `--base-url` flag form):

```bash
python recon_agents.py config set --base-url http://192.168.1.4:11434 --model qwen3:8b
python recon_agents.py config show
python recon_agents.py check-llm
```

Shell:

```text
/config set --base-url http://192.168.1.4:11434
/config show
/check-llm
```

### 17.3 What `check-llm` success looks like

```text
Effective LLM config:
source:     .../config/agent_config.json
provider:   ollama
model:      qwen3:8b
base_url:   http://192.168.1.4:11434
...
Pinging provider=ollama model=qwen3:8b base_url=http://192.168.1.4:11434 …
Ollama reachable â€” models on host: qwen3:8b, ...
OK â€” model replied: pong
```

If tags fail with connection refused, `check-llm` prints a short â€œVM → Windows
hostâ€ hint (wrong IP is the most common cause).

### 17.4 Templates

- `config/agent_config.vm-example.json` â€” sample with a host IP placeholder  
- `config/agent_config.cloud-examples.json` â€” Grok / Claude / Gemini / OpenRouter / … blocks  
- `config/agent.env.example` â€” env-var overrides + all provider API key names  

---

## 18. Upgrades Tier A–D (scoring, diff, report, jobs, agents)

These features sit on top of the core pipeline. **Reindex after scans** so scores,
diffs, and the dashboard stay current.

```text
scan → /findings reindex → /notable | /diff | /report | dashboard
```

Inline help for any of these: `/notable -h`, `/playbook --help`, etc.

---

### 18.1 Scoring & â€œnotable onlyâ€ (Tier A)

Each recon record gets a **heuristic score** (severity + type + keywords such as
takeover, AKIA, `.env`, CVE, …). Default **notable** threshold = **40**.

#### Shell examples

```text
# After any recon:
â–¸ /findings reindex

# Top interesting rows (all targets in index)
â–¸ /notable

# One target, more rows
â–¸ /notable example.com
â–¸ /notable example.com --limit 40

# Alias
â–¸ /top example.com
```

Example output shape:

```text
  [190] critical  js            secret      AKIA…
  [153] high      dns           vuln        admin… CNAME dangling.herokuapp.com
  [140] critical  nuclei        vuln        [critical] CVE-…
```

#### Dashboard examples

1. Open `http://127.0.0.1:8787/` (or `http://<VM_IP>:8787/` from host).  
2. Filter **Notable → notable only**.  
3. Table shows **SCORE** column (`â˜…` on notable rows).  
4. Combine with module/severity as needed.

#### API examples

```bash
# Notable-only page
curl "http://127.0.0.1:8787/api/records?notable=1&limit=50"

# Filtered overview KPIs
curl "http://127.0.0.1:8787/api/overview?notable=1&target=example.com"

# Minimum score
curl "http://127.0.0.1:8787/api/records?min_score=75&limit=20"
```

---

### 18.2 History & diff (Tier A)

Every successful `/findings reindex` writes a snapshot under:

```text
~/.reconkit/history/<target>/YYYYMMDD….json
~/.reconkit/history/<target>/latest.json
```

#### Shell examples

```text
# Wave 1
â–¸ /quick example.com
â–¸ /findings reindex

# Wave 2 (more modules)
â–¸ /run example.com --modules crawl,js,nuclei
â–¸ /findings reindex

# What changed between the last two snapshots?
â–¸ /diff example.com
â–¸ /delta example.com          # alias
```

Example interpretation:

```text
  new=12  gone=0  score-changed=2
  NEW:
    + [190] critical js AKIA…
    + [120] high nuclei [high] exposed-panel …
```

You need **at least two reindexes** for a target before `/diff` can compare.

#### API example

```bash
curl "http://127.0.0.1:8787/api/diff?target=example.com"
```

---

### 18.3 Report draft (Tier A)

Builds a markdown draft for humans (not auto-submit to a program).

#### Shell examples

```text
â–¸ /target example.com
â–¸ /findings reindex
â–¸ /report                         # uses /target; notable only
â–¸ /report example.com
â–¸ /report example.com --all       # include low-score rows too
â–¸ /draft example.com              # alias
```

Output file:

```text
~/.reconkit/output/example.com/report_draft.md
```

Open it in any editor; attach evidence paths from the table when writing a real report.

---

### 18.4 Playbooks (Tier A)

Named module recipes â€” no need to remember comma lists.

#### Shell examples

```text
â–¸ /playbook list
â–¸ /pb list

â–¸ /playbook run quick example.com
â–¸ /playbook run takeover-first example.com
â–¸ /playbook run js-deep example.com
â–¸ /playbook run api-surface example.com
â–¸ /playbook run vuln-pass example.com
â–¸ /playbook run passive example.com
â–¸ /playbook run content-light example.com
â–¸ /playbook run full example.com
â–¸ /playbook run ports-hint example.com   # discovery set; no dedicated naabu stage yet
```

Using session target:

```text
â–¸ /target example.com
â–¸ /playbook run quick
```

| Playbook | Modules (summary) |
|----------|-------------------|
| `quick` | subdomains, dns, httpprobe |
| `takeover-first` | same surface for CNAME focus |
| `js-deep` | httpprobe, crawl, js, params |
| `api-surface` | httpprobe, crawl, params, content, nuclei |
| `vuln-pass` | xss, sqli, ssrf_ssti, nuclei, cloud |
| `passive` | subdomains, dns, httpprobe, tls, crawl |
| `content-light` | httpprobe, content |
| `full` | all modules |
| `ports-hint` | discovery set (manual naabu optional) |

Equivalent CLI idea:

```bash
# playbook "quick" ==
python reconkit.py run --target example.com --modules subdomains,dns,httpprobe
```

---

### 18.5 Background jobs + scan progress (Tier A)

**`/run` is background by default** so the shell stays free for `/pause` `/resume`
`/stop` `/jobs`. Use `--fg` only when you want a blocking foreground run.

| Command | Mode |
|---------|------|
| `/run example.com` | **background** (default) |
| `/run example.com --bg` | background (same) |
| `/run example.com --fg` | **foreground** (blocks the shell) |
| `/quick` Â· `/full` | background (same job path) |

#### Shell examples

```text
â–¸ /run example.com --modules subdomains,dns,httpprobe
# job id printed, e.g. a1b2c3d4e5  â€” shell prompt returns immediately

â–¸ /run example.com --modules crawl,js --fg
# foreground: live \\r spinner when exclusive TTY; Ctrl+C only

â–¸ /pause
â–¸ /resume
â–¸ /stop
â–¸ /jobs
â–¸ /jobs list
â–¸ /jobs status a1b2c3d4e5
```

#### Scan progress UI (`progress_ui.py`) â€” all modules

Every recon module uses the same progress style:

| Kind | Modules | UI |
|------|---------|-----|
| **Tool checklist** | subdomains, dns, httpprobe, tls, crawl, params, xss, sqli, ssrf_ssti, nuclei, cloud, screenshots | one spinner line (live `\r`) while a tool runs Â· **one** permanent result line with bar on finish |
| **Host loop** | js, content (paths/ffuf), cloud S3 list | same spinner + host counter Â· one result line on close |

| Mode | When | What you see |
|------|------|----------------|
| **TTY (bg or fg)** | real terminal | Live braille spinner + elapsed on **one** line; erased when tool finishes |
| **non-TTY** | pipes / capture | Static rows only (no `\r`) |

Example (subdomains â€” same pattern for other multi-tool phases):

```text
[15:17:21]  â–¸  Subdomain enum Â· example.com  (8 tools)
  â ‹  1/8  subfinder     running…  00:00:12     â† live, overwritten
  âœ“  1/8  subfinder       1003  |â–ˆâ–ˆâ–ˆâ–“â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘|   12%  00:01:04
  âœ“  2/8  amass              0  |â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–“â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘â–‘|   25%  00:01:04
  …
  âœ”  |â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ|  8/8 tools  100%  7 ok Â· 1 skip
```

Env overrides:

| Env | Effect |
|-----|--------|
| `RECONKIT_BG=1` | set automatically by shell jobs |
| `RECONKIT_PROGRESS=log\|live\|off` | force progress mode |

Typical flow with dashboard in another terminal:

```text
# Terminal 1
python recon_dashboard.py

# Terminal 2
python recon_shell.py
â–¸ /run example.com --modules subdomains,httpprobe,nuclei
â–¸ /jobs
# when status=done:
â–¸ /findings reindex
# LIVE dashboard should pick up new files automatically
```

---

### 18.6 Doctor (Tier B / D)

Self-check environment + recent log patterns + optional target folder health.

#### Shell examples

```text
â–¸ /doctor
â–¸ /doctor example.com
â–¸ /diag example.com
â–¸ /doctor -h
```

Use when:

- A stage returned empty results  
- Tools look missing  
- You want hints from `~/.reconkit/logs/debug.log`  

Also re-run after problems:

```text
â–¸ /verbose 3
â–¸ /run example.com --modules subdomains
â–¸ /doctor example.com
```

---

### 18.7 Tips search / local RAG (Tier B)

Keyword search over `bug_bounty_tips.md` and optional files in
`~/.reconkit/notes/` (`.md` / `.txt`). **No external API.**

#### Shell examples

```text
â–¸ /tips subdomain takeover
â–¸ /tips jwt secrets javascript
â–¸ /tips nuclei exposed panels
â–¸ /rag xss reflected parameters
â–¸ /notes ssrf cloud metadata
```

Add your own notes:

```text
# create folder and drop markdown
~/.reconkit/notes/my_methodology.md
```

Then `/tips …` will include those chunks.

---

### 18.8 Critic â€” LLM second pass (Tier B)

Reviews an existing report with the configured LLM (detection-only advice).

#### Prerequisites

```text
â–¸ /check-llm
â–¸ /agent example.com          # creates agent_report.md
# or
â–¸ /report example.com         # creates report_draft.md
```

#### Shell examples

```text
â–¸ /critic example.com
â–¸ /review example.com
```

Writes:

```text
~/.reconkit/output/example.com/critic_review.md
```

and prints a preview. Sections typically include solid leads, possible FPs,
missing checks, suggested next modules.

---

### 18.9 Human-in-the-loop agents (Tier B)

Confirm each specialist tool step before it runs.

#### Shell examples

```text
â–¸ /agent example.com --approve
â–¸ /agent example.com --hitl --max-steps 6
```

Prompts look like:

```text
[approve] Agent 'discovery' wants modules: dns, httpprobe, tls
[approve] run these tools? [y/N/skip/quit]:
```

| Answer | Effect |
|--------|--------|
| `y` / `yes` | Run tools |
| `n` / `skip` / Enter | Skip this step |
| `quit` | Stop orchestrator |

#### CLI examples

```bash
python recon_agents.py run --target example.com --approve
python recon_agents.py run --target example.com --approve --max-steps 8 --dry-run
```

Env alternative (any agent run):

```bash
# Linux/macOS
export RECON_AGENT_APPROVE=1
python recon_agents.py run --target example.com

# Windows PowerShell
$env:RECON_AGENT_APPROVE="1"
python recon_agents.py run --target example.com
```

---

### 18.10 Rate / politeness profiles (Tier D)

Session-level profile (sets `RECON_RATE` env for this process). Advisory for
humans; stay within program RoE.

#### Shell examples

```text
â–¸ /rate
â–¸ /rate show
â–¸ /rate stealth
â–¸ /rate normal
â–¸ /rate aggressive
â–¸ /polite stealth
```

| Profile | Intent |
|---------|--------|
| `stealth` | Slower / quieter hunting style |
| `normal` | Default |
| `aggressive` | Faster; only if RoE allows |

---

### 18.11 Plugins (Tier D)

Optional drop-in commands under `plugins/`.

Example shipped file: `plugins/example_hello.py` defining `COMMANDS`.

Core works with zero plugins. To add your own:

1. Create `plugins/my_plugin.py`  
2. Export `COMMANDS = [{ "name", "usage", "summary", "handler" }, …]`  
3. Load via `plugins.load_plugin_commands()` (hook for custom shells)

---

### 18.12 End-to-end example (upgrades after a scan)

```text
python recon_shell.py

â–¸ /scope add example.com
â–¸ /target example.com
â–¸ /verbose 2
â–¸ /playbook run quick example.com
â–¸ /findings reindex
â–¸ /notable example.com
â–¸ /run example.com --modules crawl,js,nuclei --bg
â–¸ /jobs
# … wait until done …
â–¸ /findings reindex
â–¸ /diff example.com
â–¸ /report example.com
â–¸ /doctor example.com
â–¸ /tips javascript secrets
â–¸ /check-llm
â–¸ /agent example.com --approve --max-steps 4
â–¸ /critic example.com
```

Second terminal:

```bash
python recon_dashboard.py
# Filter: Notable = notable only; Module = nuclei; etc.
```

---

## 19. Prove / safe validation (v2.1)

After recon writes candidates and you reindex, **prove** builds a queue from
the findings index and runs **non-destructive** validators only.

```
recon → findings reindex → /prove queue → /prove run → /report
```

### 19.1 What is allowed vs forbidden

| Allowed (safe) | Forbidden (never auto) |
|----------------|------------------------|
| XSS unique marker reflection | sqlmap / ghauri / DB dumps |
| SSTI `{{7*7}}` → `49` canary | RCE / reverse shells |
| Nuclei artifact re-presence | Mass scanning unrelated hosts |
| Takeover DNS/HTTP fingerprints | Auto-claiming DNS / registrar |
| SSRF *review* of recon evidence | Hitting cloud metadata from prove |

Policy file: `config/exploit_policy.json` (`max_risk_class: safe`).

### 19.2 Techniques

| Technique | Input | Action |
|-----------|--------|--------|
| `xss_reflect` | XSS / dalfox findings | GET with unique marker; confirm in body |
| `ssti_math` | SSTI candidates | Inject `{{7*7}}`; look for `49` |
| `nuclei_recheck` | nuclei / vuln rows | Match local nuclei artifacts + light GET |
| `takeover_fingerprint` | CNAME / takeover rows | DNS + provider body fingerprints |
| `ssrf_canary_review` | SSRF rows | Classify evidence; **no** metadata re-probe |
| `jwt_inspect` | JWT-shaped token | Decode header/payload only (no cracking) |
| `cors_origin` | CORS candidates | Origin canary; confirm ACAO + credentials |
| `graphql_typename` | GraphQL URL | POST `{__typename}` only |
| `redirect_canary` | Redirect candidates | Bounce to OAST or `.invalid` |
| `idor_session_diff` | IDOR-shaped URL | GET with cookie A vs B (`/session`) |

### 19.3 CLI

```bash
python recon_prove.py policy
python recon_prove.py techniques
python recon_prove.py queue --target example.com
python recon_prove.py run --target example.com --dry-run
python recon_prove.py run --target example.com
python recon_prove.py run --target example.com --technique xss_reflect
python recon_prove.py list --target example.com
python recon_prove.py show --target example.com --id <proof_id>

# same via reconkit:
python reconkit.py prove queue --target example.com
python reconkit.py prove run --target example.com
```

### 19.4 Shell

```text
/prove policy
/prove techniques
/prove queue
/prove queue example.com
/prove run example.com --dry-run
/prove run example.com
/prove run example.com --technique xss_reflect --limit 10
/prove list example.com
/prove show <id>          # requires /target
/report example.com       # includes confirmed proofs when present
/playbook run prove-prep example.com   # recon modules that feed prove
```

### 19.5 Outputs

```text
~/.reconkit/output/<target>/proofs/
  proofs_index.json
  <proof_id>.json          # status, evidence, impact_note, meta
```

Statuses: `confirmed` Â· `not_exploitable` Â· `false_positive` Â· `needs_manual` Â· `skipped` Â· `error`.

### 19.6 Scope & ethics

- `/prove run` calls `require_scope_or_exit` â€” same gate as recon.  
- Prefer **notable** findings (default); use `--all` only when needed.  
- Confirmed â‰  full exploit write-up; still verify under program RoE.  
- Do not raise `max_risk_class` unless you intentionally build a lab profile later.

---

## 20. Program profiles & graph (v3.0)

### Program profiles

```text
/program list
/program show
/program set example-web
/findings reindex          # refresh weighted scores
/notable
```

```bash
export RECON_PROGRAM=example-web
# profiles: config/programs/*.json
curl -s http://127.0.0.1:8787/api/program
```

Weights boost categories (xss, takeover, secret, …) for `/notable` and prove queue order.

### Attack graph

```text
/graph summary
/graph show example.com
```

```bash
curl -s "http://127.0.0.1:8787/api/graph?target=example.com&min_score=40"
```

Dashboard → **Graph** tab (drag nodes) Â· **Insights** tab (bar charts).  
Evidence panels use JetBrains Mono on solid `#1a1d24` (see Â§13 typography).

More examples: **[OPERATIONS.md Â§9–12](OPERATIONS.md)** Â· **[WORKFLOW.md Phase H/K/L](WORKFLOW.md)**.

---

## 21. Agent skill suite

Agent Skills ([agentskills.io](https://agentskills.io)-style `SKILL.md` packs)
inject into planner / specialist / analyst / critic prompts. They work with
**local Ollama and every cloud provider**. Research inputs were the clones under
`git_skills/` (Bug-Bounty-Agents, bughunter-ai, claude-bug-bounty, Claude-BugHunter)
â€” adapted for reconkit (scope, modules, prove, findings) **without** payload zoos.

### 21.1 Core skills (role-routed)

| Skill | Roles | Purpose |
|-------|-------|---------|
| `reconkit-bug-bounty` | planner, specialist, analyst | Pipeline, scope, anti-patterns |
| `reconkit-efficiency` | planner | â‰¤3 modules/step, early-stop, token hygiene |
| `reconkit-fp-eval` | planner, specialist, analyst, critic, prove | C0–C4 tiers, kill-fast FPs |
| `reconkit-exploit-prove` | analyst, critic, prove | Canary PoC template + `/prove` technique map |
| `reconkit-triage-gate` | analyst, critic | Pre-report 7-question / N/A prevention |

### 21.2 On-demand mini-skills (max 3 / turn)

Loaded only when **modules** or **context text** match (`agents/skills.py`):

| Skill | Module triggers | Keyword examples |
|-------|-----------------|------------------|
| `reconkit-vuln-idor` | `params`, `crawl` | `user_id`, `/api/v`, BOLA |
| `reconkit-vuln-jwt` | `js` | `eyJ`, bearer, JWT |
| `reconkit-vuln-graphql` | `crawl` | graphql, introspection |
| `reconkit-vuln-ssrf` | `ssrf_ssti`, `cloud`, `nuclei` | webhook, OAST, 169.254 |
| `reconkit-vuln-xss` | `xss` | dalfox, reflected |
| `reconkit-vuln-sqli` | `sqli` | SQL error, boolean-based |
| `reconkit-vuln-takeover` | `dns`, `nuclei` | CNAME, dangling, herokuapp |
| `reconkit-vuln-secrets` | `js`, `cloud` | AKIA, private key, webhook |

### 21.3 Confidence model (C0–C4)

| Tier | Meaning | Typical next step |
|------|---------|-------------------|
| **C0** | Noise / N/A class | Drop |
| **C1** | Scanner candidate | `/prove …` or manual retest |
| **C2** | Canary re-confirmed | PoC draft (exploit-prove skill) |
| **C3** | Impact demonstrated | Human HITL + triage-gate |
| **C4** | Report-ready | Submit |

Never claim C3/C4 from nuclei alone.

```text
C1 (nuclei/xss hit)
  → /prove run --technique xss_reflect   → C2 if confirmed
  → PoC markdown (skill template)        → still C2 until impact
  → human demonstrates impact            → C3
  → triage-gate                          → C4 report
```

### 21.4 Zero-token pre-eval

Before the analyst LLM runs, `agents/eval.py` applies heuristics:

- Instant C0 kills (info-only noise, missing CSP alone, …)
- Suggests next actions like `prove:xss_reflect` for C1 rows

### 21.5 Env + inspect

```bash
# Default (on)
export RECON_AGENT_SKILL=reconkit-bug-bounty

# Disable all skill injection
export RECON_AGENT_SKILL=off

# Always merge extras
export RECON_AGENT_SKILL_EXTRA=reconkit-efficiency

# Cap injected characters (lower for small local models; cloud can be higher)
export RECON_AGENT_SKILL_MAX=14000

python recon_agents.py agents
# → primary skill path, suite by role, surface mini-skills list
```

### 21.6 Worked example (skills + prove)

```bash
# 1) Scope + recon surface that unlocks XSS mini-skill
python reconkit.py scope add example.com
python recon_agents.py config set --provider ollama \
  --base-url http://192.168.1.4:11434 --model qwen3:8b
python recon_agents.py check-llm

# 2) Agent run limited to XSS module → injects reconkit-vuln-xss (â‰¤3 surface)
python recon_agents.py run --target example.com --modules xss --max-steps 4

# 3) Index + safe prove → promote C1 → C2
python reconkit.py findings reindex
python recon_prove.py queue --target example.com --technique xss_reflect
python recon_prove.py run --target example.com --technique xss_reflect

# 4) Report + critic (triage-gate + exploit-prove skills on critic)
# shell:
#   /report example.com
#   /critic example.com
#   /dashboard   → Proofs tab status=confirmed
```

Full design notes: **[skills/README.md](skills/README.md)** Â· **[skills/SKILLS_INDEX.md](skills/SKILLS_INDEX.md)** Â· **OPERATIONS.md Â§14**.

---

## 22. Feature matrix (everything available)

| Feature | How to use | Needs LLM? |
|---------|------------|------------|
| Tool install | `/setup` Â· `reconkit.py setup` | No |
| Env check | `/checkenv` Â· `verify` | No |
| Wordlists | `/wordlists` | No |
| Scope gate | `/scope add\|list\|check` | No |
| API keys | `/keys set\|list\|remove` | No |
| Module list | `/modules` | No |
| Interactive module picker | `/scan` | No |
| Full / partial pipeline | `/run` Â· `/quick` Â· `/full` | No |
| Verbosity 0–3 / live tools | `/verbose` Â· `-v` Â· `--debug` | No |
| Multi-agent recon | `/agent` Â· `recon_agents.py run` | **Yes** |
| **Cloud LLMs** (Grok/Claude/Gemini/…) | `providers` Â· `config set --provider` | **Yes** |
| **Agent skill suite** (C0–C4 + mini-skills) | auto on `/agent` Â· `RECON_AGENT_SKILL*` | with agents |
| Agent approve (HITL) | `/agent --approve` Â· `--approve` | **Yes** |
| List specialists + skills | `/agents` Â· `recon_agents.py agents` | No |
| List LLM providers | `recon_agents.py providers` | No |
| Ping LLM | `/check-llm` | **Yes** (network) |
| Agent config | `/config show\|path\|init\|set` | No |
| Findings index | `/findings reindex\|summary` | No |
| **Notable / scores** | `/notable` Â· dashboard notable filter | No |
| **Program weights** | `/program set` Â· `RECON_PROGRAM` | No |
| **Diff / history** | `/diff <target>` | No |
| **Report draft** | `/report [target] [--all]` | No |
| **Playbooks** | `/playbook list\|run <name>` | No |
| **Background jobs** | `/run` default bg Â· `--fg` foreground Â· `/jobs` Â· `/pause` `/stop` | No |
| **Scan progress UI** | one bar per tool Â· log mode on bg Â· `progress_ui.py` | No |
| **Doctor** | `/doctor [target]` | No |
| **Tips RAG** | `/tips <query>` | No |
| **Critic** | `/critic [target]` | **Yes** |
| **Rate profile** | `/rate stealth\|normal\|aggressive` | No |
| Cyber dashboard | `/dashboard` Â· `recon_dashboard.py` | No |
| **Dashboard typography / console** | Helvetica/Inter + JetBrains Mono | No |
| **Attack graph** | `/graph` Â· dashboard Graph tab | No |
| **Insights charts** | dashboard Insights Â· `/api/stats/charts` | No |
| Inline help | `/` Â· `/help` Â· `/<cmd> -h` | No |
| **Live slash autocomplete** | type `/…` Â· contextual `--modules` / keys / providers | No |
| **Safe prove / validate** | `/prove` Â· `recon_prove.py` | No |
| **Auth session** | `/session` · `reconkit.py session` | No |
| **HAR import** | `/har import` | No |
| **Hunter inbox** | `/inbox` · dashboard **INBOX** · `/api/inbox` | No |
| **Evidence ZIP** | `/evidence` | No |
| **Resume / scope-all** | `/run --resume` · `/run --scope-all` | No |
| Session target | `/target` | No |
| Output listing | `/outdir` | No |
| Agent report | `/agent` → `agent_report.md` | **Yes** |

**Detection-only modules:** subdomains, permute, dns, ports, httpprobe, tls,
wellknown, crawl, js, jsintel, params, apis, content, bypass403, gfextra,
xss, sqli, ssrf_ssti, redirect, cors, graphql, nuclei, cloud, takeover_plus,
osint, gitrecon, screenshots  
(see §8 and [HUNTER.md](HUNTER.md)).

---

## 23. Output files cheat sheet

Under `~/.reconkit/output/<target>/`:

| File | From module / command |
|------|------------------------|
| `subdomains.txt` | subdomains |
| `dns_records.txt`, `cname_takeover_candidates.txt` | dns |
| `alive.txt` | httpprobe |
| `tls_recon.json` | tls |
| `urls.txt` | crawl |
| `js_urls.txt`, `js_secrets_and_endpoints.json` | js |
| `param_names.txt`, `arjun_params.txt` | params |
| `sensitive_paths_found.txt`, `ffuf_*.json` | content |
| `xss_reflected_params.txt`, `dalfox_results.txt` | xss |
| `sqli_*.txt` | sqli |
| `ssrf_metadata_candidates.txt`, `ssti_candidates.txt` | ssrf_ssti |
| `nuclei_*.txt` | nuclei |
| `cloud_assets.json`, `open_s3_buckets.txt` | cloud |
| `screenshots/` | screenshots |
| `permute_resolved.txt` | permute |
| `ports.txt`, `ports_http.txt` | ports |
| `waf_detected.txt` | httpprobe |
| `wellknown.txt` | wellknown |
| `js_intel.json` | jsintel |
| `api_urls.txt`, `idor_candidates.txt` | apis |
| `bypass403.txt` | bypass403 |
| `redirect_hits.txt`, `cors_candidates.txt`, `graphql_endpoints.txt` | redirect / cors / graphql |
| `takeover_plus.txt` | takeover_plus |
| `osint.txt` | osint |
| `git_urls.txt` | gitrecon |
| `wordlist_target.txt` | `/wordlist-target` |
| `evidence_*.zip` | `/evidence` |
| `agent_state.json`, `agent_report.md` | `/agent` |
| `report_draft.md` | `/report` |
| `critic_review.md` | `/critic` |
| `proofs/*.json` (under prove store) | `/prove run` |

Also:

| Path | Content |
|------|---------|
| `~/.reconkit/index/findings_index.json` | Scored recon records for dashboard |
| `~/.reconkit/history/<target>/` | Snapshots for `/diff` |
| `~/.reconkit/logs/debug.log` | Tool stderr every run |
| `~/.reconkit/notes/` | Optional notes for `/tips` |
| `~/.reconkit/session.json` | Auth cookies/headers (`/session`; never commit) |
| `skills/*/SKILL.md` | Agent skill packs (repo; not under `~/.reconkit`) |

---

## 24. Quick reference (all CLIs)

### reconkit

```bash
python reconkit.py checkenv|setup|verify|wordlists|modules
python reconkit.py scope add|list|check …
python reconkit.py keys set|list|remove …
python reconkit.py run --target T [--modules a,b|all] [--resume] [--scope-all]
python reconkit.py [-v 0-3|--debug] run --target T
python reconkit.py session show|set|clear …
python reconkit.py har --target T --file path.har
python reconkit.py evidence --target T [--id ID]
python reconkit.py wordlist-target --target T
python reconkit.py shell [--target T]
python reconkit.py dashboard [--host H] [--port P] [--no-browser] [--no-refresh]
python reconkit.py findings [summary|reindex] [target]
python reconkit.py prove policy|techniques|queue|run|list|show …
python reconkit.py --version
```

### recon_shell

```bash
python recon_shell.py [--target T] [-v 0-3] [--debug] [--no-banner]
# inside: /<cmd> -h for any command  Â·  /prove queue|run …
```

### recon_prove

```bash
python recon_prove.py policy|techniques
python recon_prove.py queue --target T [--all] [--technique xss_reflect]
python recon_prove.py run --target T [--dry-run] [--technique T] [--limit N]
python recon_prove.py list --target T
python recon_prove.py show --target T --id ID
```

### recon_agents

```bash
python recon_agents.py providers
python recon_agents.py agents|modules|check-llm
python recon_agents.py config show|path|init|set …
# config set flags (required -- form):
python recon_agents.py config set --provider ollama --base-url http://192.168.1.4:11434
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py config set --model qwen3:8b --timeout 300
python recon_agents.py check-llm [--provider P] [--model M]
python recon_agents.py run --target T [LLM flags] [--modules …] [--max-steps N]
                              [--dry-run] [--skip-analyst] [--approve] [--debug|-v N]
# one-shot cloud:
python recon_agents.py run --target T --provider anthropic --model claude-sonnet-4-20250514
```

### recon_dashboard

```bash
python recon_dashboard.py [--host 127.0.0.1] [--port 8787] [--no-browser] [--no-refresh]
# from Windows host when UI runs in VM: http://<VM_IP>:8787/
# UI: Helvetica Neue/Inter Â· evidence: JetBrains Mono #1a1d24
```

---

## 25. Safety & ethics

By design this toolkit does **not**:

- Scan out-of-scope targets (`scope` gate)
- Mass-scan the internet for random vulnerable devices
- Ship live RCE / exploitation (sqlmap, ghauri, shell SSTI, …)
- Auto-send scope data to third-party XSS callback SaaS
- Re-probe cloud metadata or auto-claim takeovers in the prove layer
- Ship weaponized payload packs in agent skills (methodology + safe prove only)

You must hold **written authorization** (bug bounty scope, pentest RoE, or your own systems) before adding targets and running modules.

Dashboard and logs may contain secrets found in JS â€” treat `~/.reconkit` as sensitive.  
Cloud API keys stay in env / local config â€” never commit them.

---

## 26. Troubleshooting

| Symptom | What to try |
|---------|-------------|
| â€œnot in scopeâ€ | `scope add` / `/scope add` and type `yes` |
| Few subdomains | Set API keys; re-run `subdomains`; check `debug.log` |
| Tool missing | `setup` then `verify`; check Go/Cargo install |
| Empty stage output | `-v 2` or `-v 3`; read `~/.reconkit/logs/debug.log` |
| Dashboard empty | Run a scan; click REINDEX or enable LIVE |
| Dashboard not updating after scan | Enable **LIVE**, or REINDEX â€” do not restart unless port is stuck; hard-refresh browser once (`Ctrl+F5`) if old JS cached |
| Dashboard fonts / console look old | `Ctrl+F5` after upgrade; expect Helvetica/Inter UI + JetBrains Mono evidence `#1a1d24` |
| Dashboard stale | Reindex after every new scan |
| LLM timeout | Raise `llm.timeout` via `/config set --timeout 300`; ensure model pulled / cloud key valid |
| **`check-llm` Connection refused (111)** | `base_url` is wrong IP. From the VM: `curl http://<WINDOWS_IP>:11434/` must succeed, then `/config set --base-url http://<WINDOWS_IP>:11434`. Do **not** use the Kali/VM IP or `127.0.0.1` |
| VM cannot reach Ollama | Same as above; on Windows: `setx OLLAMA_HOST 0.0.0.0`, restart Ollama, firewall TCP 11434, `ollama pull qwen3:8b` |
| Cloud `check-llm` auth error | Set the provider key (`XAI_API_KEY`, `ANTHROPIC_API_KEY`, …); run `providers` for the env name; `config show` |
| Cloud still uses `qwen3:8b` | After switching provider, set model explicitly or use `config set --provider xai` so the preset model applies |
| Model missing warning | On Windows: `ollama pull qwen3:8b` (tag must match `llm.model`) |
| `JSONDecodeError` / empty config | Empty `agent_config.json`. Run `config path`, then `config init --repo --force --base-url http://…` or restore from `config/agent_config.vm-example.json` |
| `/config set` did nothing | Must use **`--base-url`** not bare `base_url`; then `/config show` and re-check `config path` |
| Config file unclear | `/config path` shows which JSON is loaded |
| Skills not loading | `RECON_AGENT_SKILL` not `off`; check `python recon_agents.py agents`; packs live under `skills/` |
| Too many tokens / slow local model | Lower `RECON_AGENT_SKILL_MAX` (e.g. 8000); keep surface cap (max 3 mini-skills) |
| Shell: no live matches | `pip install prompt_toolkit`; restart in Windows Terminal / real TTY; look for `Autocomplete: LIVE âœ“`; matches appear **above** the prompt |
| Shell: `Autocomplete: OFF` | Install prompt_toolkit; avoid IDE Output panels (`NoConsoleScreenBufferError` on Windows) |
| `/diff` says need two reindexes | Run `/findings reindex` after each scan wave (twice minimum) |
| `/notable` empty | Reindex first; target may have no rows with score â‰¥ 40 |
| `/critic` fails | Need working LLM (`/check-llm`) and `agent_report.md` or `report_draft.md` |
| `/jobs` empty | Start work with `/run` first (background by default) |
| Progress bar spam / many Hosts lines | Update to latest `progress_ui.py`; bg jobs use log mode (one bar per tool). Use `/run --fg` only for exclusive live spinner |
| `--modules` suggests flags not modules | Update shell; type space after `--modules` â€” catalogs in `shell/suggestions.py` |
| Colors missing | `pip install --user colorama` or modern terminal; unset `NO_COLOR` |
| `/prove queue` empty | Run recon + `/findings reindex`; try `/prove queue --all`; need notable vuln-class findings |
| `/prove run` out of scope | `/scope add <domain>` then confirm `yes` |
| Prove confirmed but still unsure | Expected â€” canary only (C2); finish manual impact under RoE for C3 |
| Want sqlmap etc. | Not in this toolkit; use separate lab tools under your own RoE |
| Graph empty | Reindex after recon; lower min score on Graph tab; `/graph show` |
| Program weights not applied | `/program set …` then `/findings reindex` |
| Insights charts empty | Need findings in index; pick a target with data |

---

## 27. Complete operations index

Every user-facing operation (setup, scope, keys, run, shell slash commands, prove,
program, graph, dashboard API, agents, cloud providers, skills, playbooks, jobs,
plugins) is documented with **CLI and shell examples** in:

### → **[OPERATIONS.md](OPERATIONS.md)**

Ordered hunt with phase-by-phase copy-paste:

### → **[WORKFLOW.md](WORKFLOW.md)**

| Area | OPERATIONS section | WORKFLOW phase | USAGE |
|------|--------------------|----------------|-------|
| Setup / verify / wordlists | Â§3 | A–C | Â§5 |
| Scope / keys | Â§4–5 | C–D | Â§6–7 |
| Recon modules & run | Â§6 | G | Â§8–10 |
| All shell commands | Â§7 | E–O | Â§11 |
| Findings / program | Â§8–9 | H | Â§12, Â§20 |
| Prove | Â§10 | J | Â§19 |
| Graph | Â§11 | K | Â§20 |
| Dashboard + HTTP API + typography | Â§12 | L | Â§13 |
| Agents / cloud providers / check-llm | Â§13 | M | Â§14–17 |
| Agent skill suite | Â§14 | M | **Â§21** |
| Notable / diff / report / critic | Â§15 | I, N | Â§18 |
| Playbooks / jobs | Â§16 | G, N | Â§18 |

---

## Next reading

- **[OPERATIONS.md](OPERATIONS.md)** â€” exhaustive command & API examples  
- **[WORKFLOW.md](WORKFLOW.md)** â€” full hunt from setup → prove → graph → report  
- **[AGENTS.md](AGENTS.md)** â€” LLM / skills / program / prove quick start  
- **[skills/README.md](skills/README.md)** Â· **[skills/SKILLS_INDEX.md](skills/SKILLS_INDEX.md)** â€” skill suite  
- **[HUNTER.md](HUNTER.md)** — hunter extras (session, HAR, inbox, extra modules)  
- **[ROADMAP.md](ROADMAP.md)** — implemented vs still open  

Happy (authorized) hunting.

---

## 28. Hunter extras

See **[HUNTER.md](HUNTER.md)** for the full hunter/OSE walkthrough (tiers 1–4).

Quick path:

```text
/scope add example.com
/session set --cookie "sid=…"                 # optional authenticated recon
/har import ~/Downloads/app.har example.com   # optional browser export
/run example.com --modules all
# or resume after a stop:
/run example.com --resume
/findings reindex
/inbox example.com
/prove queue example.com
/prove run example.com --technique cors_origin
/evidence example.com
/dashboard   # SCAN · FINDINGS · INBOX · PROOFS · GRAPH · INSIGHTS
```

Multi-root programs:

```text
/run --scope-all --modules subdomains,dns,httpprobe
```

Two-account IDOR canary (your objects only):

```text
/session set --cookie "userA=…" --cookie-b "userB=…"
/prove run example.com --technique idor_session_diff
```
