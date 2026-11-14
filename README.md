# Reconkit

Reconnaissance engine for authorized bug bounty, VDP, and penetration tests.
Detection and safe validation only. The CLI is the engine. Findings and
proofs are `recon.py` commands. One entry point: `recon.py`.

```bash
python recon.py example.com
python recon.py example.com --modules dns,httpprobe
python recon.py example.com --review
python recon.py playbook list
```

The target must already be in `~/.reconkit/scope.txt`.

Output lands in `~/.reconkit/output/<target>/`. Each result is written once.
Per-source subdomain and crawl lists go to `tools/<stage>/<tool>.txt` as that
tool finishes. Other stage results are one file at the output root, with the
exit code in `tools/<stage>/<tool>.txt.rc`. `--review` (or
`RECON_SUPERVISOR=1`) adds a model note per phase in `reviews/<phase>.txt`
and `reviews/summary.txt` when the run finishes. A normal run does not call
a model. Ctrl+C skips the summary.

A scan prints one phase line, one row when a tool finishes, one line per
probed host, and `[+] SCAN COMPLETE`.

`python recon.py agents <target>` asks the model for the next one to three
modules, then runs those stages. It keeps walking the pipeline until nothing
runnable remains, the remaining modules are blocked for lack of hosts or URLs,
or the step cap is reached. The module order, `skip_if_chosen`, and the
dry-run rules are in [Agents](#10-agents).

`python recon.py help <command>` prints the longer help for that command.
The older form `python recon.py run --target example.com` still works.

Other docs: [AGENTS.md](AGENTS.md),
[config/CLOUD_LLM_SETUP.md](config/CLOUD_LLM_SETUP.md),
[skills/README.md](skills/README.md).

## Contents

1. [Feature list](#1-feature-list)
2. [Scan](#2-scan)
3. [Modules](#3-modules)
4. [Setup, scope, and keys](#4-setup-scope-and-keys)
5. [Workflow commands](#5-workflow-commands)
6. [Results](#6-results)
7. [Prove](#7-prove)
8. [Session, HAR, and rate](#8-session-har-and-rate)
9. [Playbooks](#9-playbooks)
10. [Agents](#10-agents)
11. [Agent skills](#11-agent-skills)
12. [Files](#12-files)
13. [Safety](#13-safety)
14. [Troubleshooting](#14-troubleshooting)
15. [One authorized hunt](#15-one-authorized-hunt)
16. [Pipeline order](#16-pipeline-order)
17. [Hunter extras](#17-hunter-extras)

---

## 1. Feature list

| Feature | Example |
|---------|---------|
| Scan | `python recon.py example.com` |
| Selected modules | `python recon.py example.com --modules dns,httpprobe` |
| Resume | `python recon.py example.com --resume` |
| Force re-run | `python recon.py run example.com --force` |
| Phase review notes | `python recon.py example.com --review` |
| Every in-scope root | `python recon.py run --scope-all --modules subdomains,dns,httpprobe` |
| Verbosity | `python recon.py -v 2 example.com` |
| Setup | `python recon.py setup` |
| Tool check | `python recon.py checkenv` |
| PATH check | `python recon.py verify` |
| Wordlists | `python recon.py wordlists` |
| Module list | `python recon.py modules` |
| Scope add | `python recon.py scope add example.com` |
| Scope list | `python recon.py scope list` |
| Scope check | `python recon.py scope check example.com` |
| API keys | `python recon.py keys set PDCP_API_KEY <token>` |
| Findings | `python recon.py findings example.com` |
| Reindex | `python recon.py findings reindex` |
| Prove | `python recon.py prove example.com` |
| Prove one technique | `python recon.py prove example.com xss_reflect` |
| Session cookie | `python recon.py session set --cookie "sid=..."` |
| HAR import | `python recon.py har --target example.com --file capture.har` |
| Evidence zip | `python recon.py evidence --target example.com` |
| Target wordlist | `python recon.py wordlist-target --target example.com` |
| Quick playbook | `python recon.py playbook run quick --target example.com` |
| Full playbook | `python recon.py playbook run full --target example.com` |
| Playbook list | `python recon.py playbook list` |
| Notable scores | `python recon.py notable --target example.com` |
| Diff | `python recon.py diff --target example.com` |
| Report draft | `python recon.py report --target example.com` |
| Program weights | `python recon.py program set example-web` |
| Inbox | `python recon.py inbox --target example.com` |
| Rate | `python recon.py rate stealth` |
| Tool caps | `python recon.py set RECON_AMASS_TIMEOUT 900` |
| Doctor | `python recon.py doctor --target example.com` |
| Tips search | `python recon.py tips reflected xss` |
| Critic | `python recon.py critic --target example.com` |
| Confidence dump | `python recon.py eval --target example.com` |
| Agent scan | `python recon.py agents example.com` |
| List agents | `python recon.py agents` |
| LLM check | `python recon.py agents check-llm` |
| LLM providers | `python recon.py agents providers` |
| LLM config | `python recon.py agents config set --provider xai --model grok-2-latest` |

A scan is the foreground process. Ctrl+C stops it. There is no interactive shell.

---

## 2. Scan

```bash
python recon.py scope add example.com
python recon.py example.com
python recon.py example.com all
python recon.py example.com --modules subdomains,dns,httpprobe,nuclei
python recon.py example.com --resume
python recon.py example.com --review
python recon.py -v 3 example.com --modules subdomains
```

| Flag | Effect |
|------|--------|
| `--modules a,b` | Those modules only. Default is `subdomains,dns,httpprobe,tls,wellknown,crawl`. `all` runs every module. |
| `--resume` | Skip a finished tool file. Exit 124 (the time cap) runs that tool again. An older run with only the merged file and no `tools/<stage>/` files still skips that stage. |
| `--force` | Re-run even when output exists. |
| `--review` | After each phase, write a model note in `reviews/<phase>.txt`. The next phase starts while the note is written. |
| `--scope-all` | Run the same modules against every root in `scope.txt`. |
| `-v 0-3` | 0 quiet, 1 normal, 2 debug, 3 live tool output. `--debug` is `-v 2`. |

`--review` uses the provider in `config/agent_config.json`. A missing key is
recorded in the note and the scan continues. The note says what landed, what
to ignore, and which existing prove technique is worth a look.
`reviews/summary.txt` is written at the end of a run that was not stopped.
Ctrl+C skips `reviews/summary.txt`.

Each result is written once. Per-source subdomain and crawl lists go to
`~/.reconkit/output/<target>/tools/<stage>/<tool>.txt` as that tool finishes,
and the merge file (`subdomains.txt`, `urls.txt`) is rebuilt from those lists.
A stage with one result writes that file at the output root (`alive.txt`,
`dns_records.txt`, `resolved.txt`, `tls_recon.json`, `wellknown.txt`) and keeps
the exit code in `tools/<stage>/<tool>.txt.rc`.

Example while subfinder is done and amass is still running:

```text
tools/subdomains/subfinder.txt
subdomains.txt          # already has subfinder names
```

A scan prints plain status lines.

```text
[*] example.com  6 modules: subdomains, dns, httpprobe, tls, wellknown, crawl
[*] Ctrl+C stops this scan
[*] 1/6 Subdomain enum  passive
[+]  1/9  subfinder           45  00:00:31
[*]  2/9  amass            skip  00:03:00  resume
[+]  9/9 tools  8 ok · 1 skip  00:04:10
[*] 3/6 HTTP probe  active
[+]  1/40  https://www.example.com  200
[-]  old.example.com  no response
[*] JS fetch/secrets  12
[+]  12/12  JS fetch/secrets  00:01:04
[+] SCAN COMPLETE  6 modules  00:12:00  ~/.reconkit/output/example.com
```

`[*]` is a phase, a skipped tool, or the start of a host loop. `[+]` is a finished tool, a host that answered, a finished host loop, or the scan complete line. `[-]` is a failed tool or a host with no response. `[!]` is a warning and prints on its own line. HTTP probe prints one line per host. A host loop such as JavaScript fetch or ffuf prints one start line and one finished count. `Ctrl+C` stops the scan.

```bash
python recon.py example.com
python recon.py playbook run quick --target example.com
python recon.py playbook run full --target example.com
```

`quick` is subdomains, dns, and httpprobe. `full` is every module.
`python recon.py modules` lists the stages.

---

## 3. Modules

`python recon.py modules`

| Module | What it writes |
|--------|----------------|
| `subdomains` | subfinder, amass, assetfinder, chaos, findomain, crt.sh, OTX, Wayback, HackerTarget |
| `permute` | Capped DNS name guesses. `dns` resolves them when both run together. |
| `dns` | One dnsx pass: records and CNAME-takeover fingerprints |
| `ports` | naabu on in-scope hosts, common web and data ports |
| `httpprobe` | httpx alive hosts, title, status, tech |
| `tls` | tlsx cert details and JARM |
| `wellknown` | robots, sitemap, security.txt, OpenID, assetlinks |
| `crawl` | katana, gospider, hakrawler, gau, waybackurls. In-scope URLs only. |
| `js` | JavaScript URL and secret/endpoint regexes |
| `jsintel` | Sourcemaps, hidden routes, API paths, library versions |
| `params` | Parameter names (unfurl) and a capped arjun pass |
| `apis` | OpenAPI, GraphQL, and IDOR-shaped parameter URLs |
| `content` | Sensitive-path httpx pass plus ffuf |
| `bypass403` | Path and header probes for 401/403. No password spray. |
| `gfextra` | gf lists for redirect, lfi, and interesting params |
| `xss` | gf xss, kxss, a unique marker, dalfox on reflected URLs |
| `sqli` | Error and boolean canaries against a baseline |
| `ssrf_ssti` | Metadata SSRF probe and an SSTI math canary |
| `redirect` | Open-redirect canary |
| `cors` | Reflected `Access-Control-Allow-Origin` check |
| `graphql` | `{__typename}` detection. No schema dump. |
| `nuclei` | CVE, takeover, panel, exposure, and tech templates |
| `cloud` | Cloud storage names and a read-only public-list check |
| `takeover_plus` | package.json and dangling JS CDN 404s. No auto-claim. |
| `osint` | Shodan or Censys limited to this hostname |
| `gitrecon` | Public git URLs and optional trufflehog on one repo |
| `screenshots` | gowitness shots of alive hosts |

---

## 4. Setup, scope, and keys

```bash
pip install prompt_toolkit colorama
python recon.py checkenv
python recon.py setup
python recon.py verify
python recon.py wordlists
```

`setup` installs Go, Rust, and Python tools, gf patterns, and nuclei templates.
Re-running it skips what is already installed. Then open a new terminal so PATH
changes apply.

```bash
python recon.py scope add example.com
python recon.py scope add example.com --yes
python recon.py scope list
python recon.py scope check example.com
```

`scope add` asks you to type `yes` unless `--yes` is set. Nothing in `run`
scans a host that is not in `~/.reconkit/scope.txt`.

```bash
python recon.py keys set PDCP_API_KEY <token>
python recon.py keys set GITHUB_TOKEN <token>
python recon.py keys list
python recon.py keys remove SHODAN_API_KEY
```

Known key names: `PDCP_API_KEY`, `GITHUB_TOKEN`, `SHODAN_API_KEY`,
`CENSYS_API_ID`, `CENSYS_API_SECRET`, `SECURITYTRAILS_API_KEY`,
`VIRUSTOTAL_API_KEY`. Values live in `~/.reconkit/secrets.env`.

```bash
python recon.py checkenv
python recon.py setup
python recon.py verify
python recon.py wordlists
python recon.py scope add example.com
python recon.py scope list
python recon.py scope check example.com
python recon.py keys list
```

---

## 5. Workflow commands

```bash
python recon.py playbook list
python recon.py playbook run js-deep --target example.com
python recon.py rate show
python recon.py rate stealth
python recon.py set
python recon.py set RECON_AMASS_TIMEOUT 900
python recon.py doctor --target example.com
python recon.py -v 2 example.com
```

`-v` is 0 quiet, 1 normal, 2 debug, 3 live tool output. `rate` and `set`
are stored in `~/.reconkit/config.json` and apply on the next scan. Output
for a target is `~/.reconkit/output/<target>/`.

---

## 6. Results

Reindex after a scan so scores, diffs, and prove see the new files.

```bash
python recon.py findings reindex
python recon.py findings example.com
python recon.py notable --target example.com --limit 40
python recon.py diff --target example.com
python recon.py report --target example.com
python recon.py report --target example.com --all
python recon.py inbox --target example.com
python recon.py eval --target example.com
python recon.py program list
python recon.py program show
python recon.py program set example-web
```

| Command | Result |
|---------|--------|
| `findings reindex` | Rebuild `~/.reconkit/index/findings_index.json` and the SQLite index |
| `findings <target>` | Count, modules, severity, and the first high or medium rows |
| `notable` | Rows with score at least 40 (35 when program `example-web` is set) |
| `diff` | New, gone, and score changes since the previous reindex. Needs two reindexes. |
| `report` | `report_draft.md` in the target folder. Notable rows unless `--all`. |
| `inbox` | C2 proofs first, then high-score C1 rows, each with a prove technique |
| `eval` | Local C0-C4 labels. `--llm` asks the configured model about borderline rows. |

Profiles are `config/programs/*.json`. `RECON_PROGRAM=example-web` is the same
switch. Set the profile, then reindex, or the weights are not in the scores.

```bash
python recon.py evidence --target example.com
python recon.py evidence --target example.com --id <finding-id>
python recon.py wordlist-target --target example.com
python recon.py doctor --target example.com
python recon.py tips reflected xss
python recon.py critic --target example.com
```

`evidence` writes a zip of recon output and proofs, skipping other zips and
files over 4 MB. `wordlist-target` builds a wordlist from crawl paths and
parameter names. `doctor` checks tools, the debug log, and that target folder.
`tips` searches `skills/` and `~/.reconkit/notes`. `critic` reviews
`agent_report.md` or `report_draft.md` with the configured model.

---

## 7. Prove

Safe checks only. No sqlmap, shells, or dumps. The target must be in scope.

```bash
python recon.py prove techniques
python recon.py prove policy
python recon.py findings reindex
python recon.py prove queue example.com
python recon.py prove example.com
python recon.py prove example.com xss_reflect
python recon.py prove example.com --dry-run
python recon.py prove list example.com
python recon.py prove show example.com <proof-id>
python recon.py prove run --target example.com --dry-run
python recon.py prove run --target example.com --technique xss_reflect --limit 10
```

| Technique | Check |
|-----------|--------|
| `xss_reflect` | Unique marker reflection |
| `ssti_math` | Math canary, not code execution |
| `nuclei_recheck` | Re-request a nuclei hit |
| `takeover_fingerprint` | CNAME fingerprint only. No claim. |
| `ssrf_canary_review` | Review an OAST or callback lead. No metadata blast. |
| `sqli_boolean` | Off unless `allow_sqli_boolean` is true in `config/exploit_policy.json` |
| `jwt_inspect` | Read the token. No key guessing. |
| `cors_origin` | Origin reflection |
| `graphql_typename` | `{__typename}` only |
| `redirect_canary` | Redirect to a canary host |
| `idor_session_diff` | Cookie A vs cookie B on your own objects |

`idor_session_diff` needs both cookies:

```bash
python recon.py session set --cookie "userA=..." --cookie-b "userB=..."
python recon.py prove example.com idor_session_diff
```

Proof JSON is `~/.reconkit/output/<target>/proofs/`. Status is one of
`confirmed`, `not_exploitable`, `false_positive`, `needs_manual`, `skipped`,
`error`.

---

## 8. Session, HAR, and rate

```bash
python recon.py session show
python recon.py session set --cookie "sid=..." --header "Authorization: Bearer ..."
python recon.py session set --cookie "userA=..." --cookie-b "userB=..."
python recon.py session clear
python recon.py har --target example.com --file capture.har
```

```bash
python recon.py rate show
python recon.py rate stealth
python recon.py set
python recon.py set RECON_AMASS_TIMEOUT 900
```

Cookies stay in `~/.reconkit/session.json` (chmod 600). HAR import keeps
in-scope URLs and can copy a Cookie into the session. `rate` stores stealth,
normal, or aggressive in the reconkit config. Stealth lowers concurrency and
adds delay. Aggressive is faster and still has to stay inside the program
rules. `set` stores a tool time cap. The new value applies the next time that
tool starts, including the next run.

Amass accepts 30 to 900 seconds. The default Amass cap is 180 seconds. dnsx,
httpx, tlsx, crawl, and each nuclei pack have their own caps:
`RECON_DNSX_TIMEOUT`, `RECON_HTTPX_TIMEOUT`, `RECON_TLSX_TIMEOUT`,
`RECON_CRAWL_TIMEOUT`, `RECON_NUCLEI_TIMEOUT`. A cap records exit 124 beside
that tool file, and `--resume` runs the tool again. When httpx hits the cap
and `alive.txt` already lists hosts, the previous host list stays.

---

## 9. Playbooks

```bash
python recon.py playbook list
python recon.py playbook run quick --target example.com
python recon.py playbook run js-deep --target example.com
python recon.py playbook run prove-prep --target example.com
```

| Playbook | Modules |
|----------|---------|
| `quick` | subdomains, dns, httpprobe |
| `passive` | subdomains, dns, httpprobe, tls, wellknown, crawl |
| `takeover-first` | subdomains, dns, httpprobe, crawl, takeover_plus |
| `js-deep` | httpprobe, crawl, js, jsintel, params |
| `api-surface` | httpprobe, crawl, js, jsintel, params, apis, graphql, cors, nuclei |
| `content-light` | httpprobe, wellknown, content, bypass403 |
| `ports-hint` | subdomains, dns, ports, httpprobe, tls |
| `auth-surface` | httpprobe, crawl, js, jsintel, apis, bypass403. Set the session first. |
| `vuln-pass` | xss, sqli, ssrf_ssti, redirect, cors, graphql, nuclei, cloud |
| `prove-prep` | httpprobe, crawl, xss, sqli, ssrf_ssti, redirect, cors, graphql, nuclei, cloud |
| `hunter` | enum, permute, ports, crawl, JS intel, APIs, 403, takeover extras |
| `full` | every module |

A playbook run is a foreground scan of that module list. Ctrl+C stops it.
`hunter` includes enum, crawl, and js so the extra modules have inputs.

---

## 10. Agents

The agent loop plans modules, runs the same recon stages, then writes
`agent_report.md`. Tool steps do not call the model.

`python recon.py <target>` runs the module list in order and does not call a
model. `python recon.py agents <target>` asks the model for the next one to
three modules, then runs those same stages.

```bash
python recon.py agents
python recon.py agents providers
python recon.py agents check-llm
python recon.py agents example.com
python recon.py agents example.com xss --max-steps 4
python recon.py agents example.com --dry-run
python recon.py agents example.com --approve
python recon.py agents config show
python recon.py agents config set --provider xai --model grok-2-latest
python recon.py agents config set --provider ollama --base-url http://192.168.1.4:11434 --model qwen3:8b
python recon.py critic --target example.com
```

| Piece | Role |
|-------|------|
| planner | Picks the next modules from file counts |
| subdomain | subdomains, permute |
| discovery | dns, ports, httpprobe, tls, wellknown, osint |
| content | crawl, js, jsintel, params, apis, content, bypass403, gfextra |
| vuln | xss, sqli, ssrf_ssti, redirect, cors, graphql, nuclei, cloud, takeover_plus, gitrecon |
| visual | screenshots |
| analyst | Final `agent_report.md` |

### How a run proceeds

`python recon.py agents example.com` asks the model which modules to run next. Python then runs those reconkit stages. The planner only chooses the batch.

1. The planner receives `reconkit-bug-bounty` and `reconkit-efficiency`, plus one vuln skill when a finished module matches. It answers with one JSON object: `done`, one specialist, and one to three module names.
2. Python runs that batch and writes the usual output files.
3. The next planner call sees the new file counts. The loop repeats until no runnable module remains, every remaining runnable module is listed in `skip_if_chosen`, or `max_steps` is reached. The default is 12 (`python recon.py agents config set --max-steps 20`, or `--max-steps` on the run).
4. The analyst writes `agent_report.md`. That call is the one that loads `phase-06-triage.md`. The planner call carries the skill files only.

A planner answer of `done: true` is ignored while a runnable module is still outside `skip_if_chosen`. The fallback batch order is:

```text
subdomains
dns + httpprobe
tls
crawl
js + params + content
nuclei + xss + sqli, then the rest of the vuln modules
screenshots
```

The model can still name a different valid batch of one to three modules owned by one specialist. `skip_if_chosen` is part of the planner brief:

| Condition | Modules held back |
|-----------|-------------------|
| `alive.txt` has no lines | tls, wellknown, crawl, content, bypass403, cors, nuclei, screenshots |
| `urls.txt` has no lines | js, jsintel, params, apis, gfextra, xss, sqli, ssrf_ssti, redirect, graphql, cloud, takeover_plus, gitrecon |
| No `graphql` token in the alive, tech-route, or URL head | graphql |

`~/.reconkit/output/<target>/agent_state.json` remembers completed modules. A non-empty output file from an earlier `python recon.py example.com` scan marks that module complete on the next agent load, so the agent does not repeat it. Delete that target's output directory to start clean.

`--dry-run` prints the batches and does not run tools. Those planned modules are dropped from `agent_state.json` on the next load when the output file is missing, so a later real run still executes them. `--approve` asks before each tool batch. `--modules a,b` limits what the planner may choose. `--skip-analyst` skips `agent_report.md`.

Set the provider key in the environment before `config set` (`XAI_API_KEY`,
`ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`,
`GROQ_API_KEY`). From a VM, Ollama's base URL is the Windows host IP, not the
VM address. Cloud setup notes are in [config/CLOUD_LLM_SETUP.md](config/CLOUD_LLM_SETUP.md).

---

## 11. Agent skills

Two packs are loaded on model calls.

Reconkit skills (`skills/<name>/SKILL.md`) follow the role. The default budget
is 8000 characters (`RECON_AGENT_SKILL_MAX`). One vuln file is attached when a
finished module matches (`RECON_AGENT_SKILL_SURFACE`).

| Skill | When |
|-------|------|
| `reconkit-bug-bounty` | Planner |
| `reconkit-efficiency` | Planner |
| `reconkit-fp-eval` | Analyst, critic, review, prove |
| `reconkit-exploit-prove` | Analyst, prove |
| `reconkit-triage-gate` | Analyst, critic |
| `reconkit-vuln-xss` | Module `xss` |
| `reconkit-vuln-sqli` | Module `sqli` |
| `reconkit-vuln-ssrf` | `ssrf_ssti`, cloud, nuclei |
| `reconkit-vuln-jwt` | `js` plus a bearer or `eyJ` |
| `reconkit-vuln-secrets` | `js`, cloud, gitrecon |
| `reconkit-vuln-idor` | `params`, crawl, apis |
| `reconkit-vuln-graphql` | crawl, graphql, apis |
| `reconkit-vuln-takeover` | `dns`, nuclei, takeover_plus |

`RECON_AGENT_SKILL=off` skips this pack. `RECON_AGENT_SKILL_EXTRA=name` always
adds that file.

Hunt phases in `skills/bug-bounty-hunting-prompts/phases/` are attached in full.
The 8000-character budget does not cut them. `ADAPTATION.md` is attached with
the phase. `RECON_AGENT_HUNT_PHASE=off` skips the pack.
`RECON_AGENT_HUNT_PHASE=phase-00-recon` forces one file.

| Call | Phase file |
|------|------------|
| Planner | none. The skill files carry the module pipeline. |
| Analyst | `phase-06-triage.md` |
| Critic | `phase-09-triage-gate.md` |
| Review (`--review`) | `phase-06-triage.md` |
| Review of crawl, js, or screenshots | `phase-04a-scope.md`, then `phase-06-triage.md` |

```bash
python recon.py agents
```

Confidence used by the skills and by `python recon.py eval`:

| Tier | Meaning | Next step |
|------|---------|-----------|
| C0 | Noise | Drop |
| C1 | Scanner candidate | `python recon.py prove` or a manual check |
| C2 | Canary confirmed | Proof is in `proofs/` |
| C3 | Impact shown by a person | Notes under the program rules |
| C4 | Ready to submit | `python recon.py critic` and `python recon.py report` |

---

## 12. Files

```text
recon.py
src/                 reconkit, prove, agents, findings, hunter, programs
skills/              SKILL.md packs and bug-bounty-hunting-prompts/
config/              agent_config.json, exploit_policy.json, programs/
```

```text
~/.reconkit/
  scope.txt
  secrets.env
  session.json
  config.json
  agent_config.json
  wordlists/
  logs/debug.log
  index/findings_index.json
  history/<target>/
  notes/
  output/<target>/
    subdomains.txt
    resolved.txt
    dns_records.txt
    alive.txt
    urls.txt
    tls_recon.json
    wellknown.txt
    diff_assets.json
    run_meta.json
    tools/<stage>/<tool>.txt       per-source lists (subdomains, crawl)
    tools/<stage>/<tool>.txt.rc     exit code for --resume
    reviews/<phase>.txt
    proofs/
    report_draft.md
    agent_report.md
    critic_review.md
```

`subdomains.txt.prev`, `resolved.txt.prev`, `alive.txt.prev`, and
`urls.txt.prev` are the previous copies used to write `diff_assets.json`.
The first scan writes an empty diff. Alive hosts are compared by hostname.
`python recon.py diff` compares findings after two reindexes.

`tools/<stage>/<tool>.txt.rc` is that tool's exit code. `124` means
`--resume` runs it again. A missing marker counts as finished. A missing
httpx or crawler leaves `alive.txt` and `urls.txt` in place. `alive_urls.txt`
is written when nuclei or screenshots need a URL-only list.

`run_meta.json` records the run. `tech_routes.txt` lists prove techniques that
match files already on disk. `param_priority.txt` is a short parameter list.
`tools/<stage>/dropped.txt` records out-of-scope and wildcard drops (capped).

| File | Module |
|------|--------|
| `permute_resolved.txt` | permute |
| `ports.txt`, `ports_http.txt` | ports |
| `waf_detected.txt` | httpprobe |
| `wellknown.txt` | wellknown |
| `js_intel.json`, `api_paths.txt` | jsintel |
| `api_urls.txt`, `idor_candidates.txt` | apis |
| `bypass403.txt` | bypass403 |
| `redirect_candidates.txt`, `lfi_candidates.txt`, `interesting_params.txt` | gfextra |
| `redirect_hits.txt` | redirect |
| `cors_candidates.txt` | cors |
| `graphql_endpoints.txt` | graphql |
| `nuclei_tech.txt` | nuclei (tech tags) |
| `takeover_plus.txt` | takeover_plus |
| `osint.txt` | osint |
| `git_urls.txt`, `trufflehog.jsonl` | gitrecon |
| `wordlist_target.txt` | `python recon.py wordlist-target` |
| `evidence_*.zip` | `python recon.py evidence` |

Session file: `~/.reconkit/session.json` (not under output/).

---

## 13. Safety

- Written authorization before `scope add`.
- Scope is checked on scan, prove, HAR import, and agents (`~/.reconkit/scope.txt`).
- Session cookies live in `~/.reconkit/session.json` (chmod 600). Never commit that file.
- API keys stay in `~/.reconkit/secrets.env`. Cloud keys stay out of the repo.
- Prove stays on the technique list in `config/exploit_policy.json`.
- OSINT (Shodan/Censys) is limited to this hostname.
- GraphQL prove is `{__typename}` only.
- IDOR prove compares your two sessions.
- JWT prove decodes the header and payload only. No key guessing, and `alg=none` stays `needs_manual`.
- No sqlmap, shells, dumps, credential spray, or internet-wide scans.

---

## 14. Troubleshooting

| What you see | What to do |
|--------------|------------|
| not in scope | `python recon.py scope add example.com` and type `yes` |
| few subdomains | `python recon.py keys list`, then re-run `subdomains` |
| tool missing | `python recon.py setup`, then `python recon.py verify` |
| empty stage | `python recon.py -v 2 example.com` and read `~/.reconkit/logs/debug.log` |
| findings look old | `python recon.py findings reindex` |
| diff wants two reindexes | Reindex once after each scan |
| notable is empty | Reindex. Rows under the score floor are hidden. |
| prove queue is empty | Reindex, then `python recon.py prove queue --target example.com --all` |
| prove says out of scope | `scope add`, then confirm |
| critic fails | `python recon.py agents check-llm`, and an `agent_report.md` or `report_draft.md` |
| agent run starts no tools | That target already has output files or completed modules in `agent_state.json`. Delete `~/.reconkit/output/<target>/` to start clean, or pass modules that have not run. |
| agent stops while modules remain | The step cap was reached. Run `python recon.py agents example.com --max-steps 20`. |
| agent skips crawl, nuclei, or xss | `alive.txt` or `urls.txt` is empty, so those modules are in `skip_if_chosen`. Re-run HTTP probe or crawl, then start the agent again. |
| program weights missing | `python recon.py program set example-web`, then reindex |
| check-llm connection refused | From a VM, set `--base-url` to the Windows host IP, not the VM IP |
| cloud auth error | Export the provider key, then `python recon.py agents check-llm` |
| no color | `pip install colorama` |

---

## 15. One authorized hunt

```bash
python recon.py checkenv
python recon.py setup
python recon.py verify
python recon.py scope add example.com
python recon.py example.com --modules subdomains,dns,httpprobe,crawl,nuclei
python recon.py findings reindex
python recon.py findings example.com
python recon.py prove example.com --dry-run
python recon.py notable --target example.com
python recon.py inbox --target example.com
python recon.py report --target example.com
```

---

## 16. Pipeline order

```text
subdomains -> permute -> dns -> httpprobe -> (tls, wellknown, ports, crawl)
         -> js -> jsintel -> params -> apis -> content -> bypass403 -> gfextra
         -> xss -> sqli -> ssrf_ssti -> redirect -> cors -> graphql
         -> nuclei -> cloud -> takeover_plus -> osint -> gitrecon -> screenshots
```

Passive name sources run together. Amass uses its own cap inside that pool.
One dnsx pass writes resolved hosts, records, and CNAME lines. httpx probes
before naabu. tls, well-known, ports, and crawl overlap after `alive.txt` and
join before js. xss, sqli, ssrf, and gfextra share one URL classification.

List descriptions anytime: `python recon.py modules`.

---

## 17. Hunter extras

Use Tier 1 first, then 2, 3, and 4. These are the same modules and commands
as the sections above, grouped the way a hunt usually grows. Safety rules are
in [Safety](#13-safety).

### Tier 1 -- authenticated surface and high-signal extras

| Feature | How |
|---------|-----|
| Auth session (cookie A + headers) | `python recon.py session set --cookie "..." --header "Authorization: Bearer ..."` |
| Multi-scope run | `python recon.py run --scope-all --modules subdomains,dns,httpprobe` |
| JS intel (maps, routes, lib versions) | module `jsintel` |
| API / OpenAPI / IDOR-shaped URLs | module `apis` |
| Extra takeover (package.json, CDN 404) | module `takeover_plus` |
| Tech-tagged nuclei pack | automatic inside `nuclei` when httpx tech matches |
| Safe 401/403 header/path probes | module `bypass403` (no password spray) |

```bash
python recon.py session set --cookie "sid=abc"
python recon.py example.com --modules httpprobe,crawl,js,jsintel,apis,bypass403
python recon.py playbook run auth-surface --target example.com
```

```bash
python recon.py session set --cookie "sid=abc" --header "Authorization: Bearer ..."
python recon.py run --target example.com --modules jsintel,apis,bypass403,takeover_plus
python recon.py run --scope-all --modules subdomains,dns,httpprobe
```

### Tier 2 -- more surface, still in scope

| Feature | How |
|---------|-----|
| Capped DNS permutations | module `permute` (alterx/dnsgen; dnsx only if dns is not in the same run) |
| In-scope port probe | module `ports` (naabu connect-scan + httpx) |
| gf extras (redirect / lfi / interestingparams) | module `gfextra` |
| Well-known / robots / security.txt | module `wellknown` |
| Scoped Shodan/Censys | module `osint` (hostname query only) |
| GitHub/GitLab URLs + optional trufflehog | module `gitrecon` (one public repo) |
| WAF backoff | httpprobe writes `waf_detected.txt`; Cloudflare -> `python recon.py rate stealth` |

```bash
python recon.py playbook run hunter --target example.com
python recon.py playbook run ports-hint --target example.com
python recon.py example.com --modules permute,ports,wellknown,gfextra,osint,gitrecon
```

### Tier 3 -- safe prove extras (C1 -> C2)

Set `oast_base_url` in `config/exploit_policy.json` for redirect and SSRF canaries.

| Technique | Input | Action |
|-----------|--------|--------|
| `jwt_inspect` | JWT-shaped token in evidence | Decode header/payload only (`alg=none` stays needs_manual) |
| `cors_origin` | CORS candidate | Origin canary; confirm ACAO + credentials |
| `graphql_typename` | GraphQL URL | POST `{__typename}` only |
| `redirect_canary` | Redirect candidate | Bounce to OAST or `.invalid` |
| `idor_session_diff` | IDOR-shaped URL | GET with cookie A vs cookie B |

Matching recon modules: `redirect`, `cors`, `graphql` (detection), then `python recon.py prove`.

```bash
python recon.py session set --cookie "userA=..." --cookie-b "userB=..."
python recon.py findings reindex
python recon.py prove queue example.com
python recon.py prove run --target example.com --technique cors_origin
python recon.py prove run --target example.com --technique idor_session_diff
```

```bash
python recon.py prove run --target example.com --technique jwt_inspect
python recon.py prove run --target example.com --technique graphql_typename
python recon.py prove run --target example.com --technique redirect_canary
```

### Tier 4 -- hunt ops (HAR, resume, evidence, inbox)

| Feature | How |
|---------|-----|
| HAR import | `python recon.py har --target example.com --file capture.har` keeps in-scope URLs in `urls.txt` and can copy a Cookie into the session |
| Target wordlist | `python recon.py wordlist-target --target example.com` writes `wordlist_target.txt` |
| Resume a partial run | `python recon.py example.com --resume` skips a finished tool file. Exit 124 runs that tool again. `--force` redoes the work. |
| Evidence ZIP | `python recon.py evidence --target example.com` writes `evidence_<target>_....zip` |
| Notify | if the `notify` CLI is installed, a C1+ vuln count is sent at the end of a successful run |
| Hunter inbox | `python recon.py inbox --target example.com` |

```bash
python recon.py har --target example.com --file ~/Downloads/app.har
python recon.py example.com --resume --modules crawl,js,jsintel,apis
python recon.py findings reindex
python recon.py inbox --target example.com
python recon.py evidence --target example.com
```

```bash
python recon.py har --target example.com --file capture.har
python recon.py run --target example.com --resume
python recon.py wordlist-target --target example.com
python recon.py evidence --target example.com
```
