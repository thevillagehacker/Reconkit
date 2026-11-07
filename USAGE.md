# reconkit usage

Authorized recon for bug bounty, VDP, and pentest scope. Detection and safe
validation only. One entry point: `recon.py`.

```bash
python recon.py
python recon.py example.com
python recon.py example.com --modules dns,httpprobe
```

The target must already be in `~/.reconkit/scope.txt`. Output is
`~/.reconkit/output/<target>/`. A normal scan does not call a model.

`python recon.py help <command>` prints the longer help for that command.
Inside the shell, `/<command> -h` does the same. The older form
`python recon.py run --target example.com` still works.

Other docs: [AGENTS.md](AGENTS.md), [OPERATIONS.md](OPERATIONS.md),
[WORKFLOW.md](WORKFLOW.md), [HUNTER.md](HUNTER.md), [skills/README.md](skills/README.md).

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
| Shell | `python recon.py shell` |
| Quick scan | `/quick example.com` |
| Full scan | `/full example.com` |
| Module picker | `/scan example.com` |
| Notable scores | `/notable example.com` |
| Diff | `/diff example.com` |
| Report draft | `/report example.com` |
| Attack graph | `/graph show example.com` |
| Program weights | `/program set example-web` |
| Inbox | `/inbox example.com` |
| Playbook | `/playbook run js-deep example.com` |
| Background job | `/jobs` |
| Pause / stop | `/pause`  /  `/stop` |
| Rate | `/rate stealth` |
| Doctor | `/doctor example.com` |
| Tips search | `/tips reflected xss` |
| Critic | `/critic example.com` |
| Confidence dump | `/eval example.com` |
| Agent scan | `python recon.py agents example.com` |
| List agents | `python recon.py agents` |
| LLM check | `python recon.py agents check-llm` |
| LLM providers | `python recon.py agents providers` |
| LLM config | `python recon.py agents config set --provider xai --model grok-2-latest` |

Shell commands that have no one-line CLI (`/notable`, `/diff`, `/graph`,
`/report`, `/playbook`, `/jobs`, `/rate`, `/doctor`, `/tips`, `/critic`,
`/eval`, `/inbox`, `/program`) run after `python recon.py shell`.

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
| `--resume` | Skip a tool whose output file is already non-empty. |
| `--force` | Re-run even when output exists. |
| `--review` | After each phase, write a model note in `reviews/<phase>.txt`. The next phase starts while the note is written. |
| `--scope-all` | Run the same modules against every root in `scope.txt`. |
| `-v 0-3` | 0 quiet, 1 normal, 2 debug, 3 live tool output. `--debug` is `-v 2`. |

`--review` uses the provider in `config/agent_config.json`. A missing key is
recorded in the note and the scan continues. `/stop` skips `reviews/summary.txt`.

Each tool writes `~/.reconkit/output/<target>/tools/<stage>/<tool>.txt` when it
finishes. The shell shows one progress line per tool.

```text
python recon.py shell
> /run example.com
> /jobs
> /pause
> /resume
> /stop
> /run example.com --fg
> /quick example.com
> /full example.com
> /scan example.com
```

`/run` is a background job. `/quick` is subdomains, dns, and httpprobe.
`/full` is every module. `/scan` is the module picker. `--fg` blocks the shell
until the scan finishes.

---

## 3. Modules

`python recon.py modules`

| Module | What it writes |
|--------|----------------|
| `subdomains` | subfinder, amass, assetfinder, chaos, findomain, crt.sh, Wayback, HackerTarget |
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

```text
> /checkenv
> /setup
> /verify
> /wordlists
> /scope add example.com
> /scope list
> /scope check example.com
> /keys list
```

---

## 5. Shell session

```bash
python recon.py shell
python recon.py shell example.com
```

| Command | Example |
|---------|---------|
| `/target example.com` | Active target for later commands |
| `/verbose 2` | 0 quiet, 1 normal, 2 debug, 3 live tools |
| `/status` | Target, verbose level, paths, LLM config |
| `/outdir example.com` | List that target's output folder |
| `/banner` | Redraw the banner |
| `/clear` | Clear the terminal |
| `/commands` | Every slash name |
| `/help run` | Same as `/run -h` |
| `/exit` | Leave the shell |

Autocomplete needs `prompt_toolkit`. Type `/co` to see matches.

---

## 6. Results

Reindex after a scan so scores, diffs, the graph, and prove see the new files.

```bash
python recon.py findings reindex
python recon.py findings example.com
```

```text
> /findings reindex
> /findings example.com
> /findings example.com --min-confidence C1
> /findings example.com --all
> /notable example.com
> /notable example.com --limit 40
> /top example.com
> /diff example.com
> /report example.com
> /report example.com --all
> /inbox example.com
> /eval example.com
> /graph summary
> /graph show example.com
> /graph show example.com --min-score 40
```

| Command | Result |
|---------|--------|
| `/findings reindex` | Rebuild `~/.reconkit/index/findings_index.json` and the SQLite index |
| `/findings <target>` | Summary for that target. Default floor is C1. `--all` drops the floor. |
| `/notable` | Rows with score at least 40 (35 when program `example-web` is set) |
| `/diff` | New, gone, and score changes since the previous reindex. Needs two reindexes. |
| `/report` | `report_draft.md` in the target folder. Notable rows unless `--all`. |
| `/inbox` | C2 proofs first, then high-score C1 rows, each with a `/prove` technique |
| `/eval` | Local C0-C4 labels. `--llm` asks the configured model about borderline rows. |
| `/graph show` | Target, host, finding, and proof links. `--min-score 40` hides low scores. |

```text
> /program list
> /program show
> /program set example-web
> /findings reindex
> /notable example.com
```

Profiles are `config/programs/*.json`. `RECON_PROGRAM=example-web` is the same
switch. Set the profile, then reindex, or the weights are not in the scores.

```bash
python recon.py evidence --target example.com
python recon.py evidence --target example.com --id <finding-id>
python recon.py wordlist-target --target example.com
```

```text
> /evidence example.com
> /wordlist-target example.com
> /doctor example.com
> /tips reflected xss
> /critic example.com
```

`/evidence` writes a zip of recon output and proofs, skipping other zips and
files over 4 MB. `/wordlist-target` builds a wordlist from crawl paths and
parameter names. `/doctor` checks tools, the debug log, and that target folder.
`/tips` searches `skills/` and `~/.reconkit/notes`. `/critic` reviews
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
```

```text
> /prove techniques
> /prove policy
> /prove queue example.com
> /prove run example.com --dry-run
> /prove run example.com --technique xss_reflect --limit 10
> /prove list example.com
> /prove show <id>
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

```text
> /session show
> /session set --cookie "sid=..."
> /session clear
> /har import capture.har example.com
> /rate show
> /rate stealth
> /rate normal
> /rate aggressive
```

Cookies stay in `~/.reconkit/session.json`. HAR import keeps in-scope URLs and
can copy a Cookie into the session. `/rate` stores stealth, normal, or
aggressive in the reconkit config. Stealth lowers concurrency and adds delay.
Aggressive is faster and still has to stay inside the program rules.

---

## 9. Playbooks and jobs

```text
> /playbook list
> /playbook run quick example.com
> /playbook run js-deep example.com
> /playbook run prove-prep example.com
> /jobs
> /jobs status <id>
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
| `auth-surface` | httpprobe, crawl, js, jsintel, apis, bypass403. Set `/session` first. |
| `vuln-pass` | xss, sqli, ssrf_ssti, redirect, cors, graphql, nuclei, cloud |
| `prove-prep` | httpprobe, crawl, xss, sqli, ssrf_ssti, redirect, cors, graphql, nuclei, cloud |
| `hunter` | enum, permute, ports, crawl, JS intel, APIs, 403, takeover extras |
| `full` | every module |

`/run` is a background job. `/pause` holds it, `/resume` continues, `/stop`
kills the tool process.

---

## 10. Agents

The agent loop plans modules, runs the same recon stages, then writes
`agent_report.md`. Tool steps do not call the model.

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
```

```text
> /agents
> /check-llm
> /config show
> /config set --provider xai --model grok-2-latest
> /agent example.com --max-steps 8
> /agent example.com --modules xss --dry-run
> /agent example.com --approve
> /critic example.com
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
| Planner | `phase-00-recon.md` |
| Planner, after crawl, js, or screenshots | `phase-04a-scope.md`, then `phase-00-recon.md` |
| Analyst | `phase-06-triage.md` |
| Critic | `phase-09-triage-gate.md` |
| Review (`--review`) | `phase-06-triage.md` |
| Review of crawl, js, or screenshots | `phase-04a-scope.md`, then `phase-06-triage.md` |

```bash
python recon.py agents
```

Confidence used by the skills and by `/eval`:

| Tier | Meaning | Next step |
|------|---------|-----------|
| C0 | Noise | Drop |
| C1 | Scanner candidate | `/prove` or a manual check |
| C2 | Canary confirmed | Proof is in `proofs/` |
| C3 | Impact shown by a person | Notes under the program rules |
| C4 | Ready to submit | `/critic` and `/report` |

---

## 12. Files

```text
recon.py
src/                 reconkit, shell, prove, agents, findings, graph, hunter, programs
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
    alive.txt
    urls.txt
    tools/<stage>/<tool>.txt
    reviews/<phase>.txt
    proofs/
    report_draft.md
    agent_report.md
    critic_review.md
```

`subdomains.txt.prev`, `alive.txt.prev`, and `urls.txt.prev` are the previous
run, kept for `/diff`.

---

## 13. Safety

- Written authorization before `scope add`.
- Scope is checked on scan, prove, and agents.
- Prove stays on the technique list in `config/exploit_policy.json`.
- No sqlmap, shells, dumps, or internet-wide scans.
- API keys and session cookies stay under `~/.reconkit/`, not in the repo.

---

## 14. Troubleshooting

| What you see | What to do |
|--------------|------------|
| not in scope | `python recon.py scope add example.com` and type `yes` |
| few subdomains | `python recon.py keys list`, then re-run `subdomains` |
| tool missing | `python recon.py setup`, then `python recon.py verify` |
| empty stage | `python recon.py -v 2 example.com` and read `~/.reconkit/logs/debug.log` |
| `/findings` looks old | `python recon.py findings reindex` |
| `/diff` wants two reindexes | Reindex once after each scan |
| `/notable` is empty | Reindex. Rows under the score floor are hidden. |
| `/prove queue` is empty | Reindex, then `/prove queue example.com --all` |
| prove says out of scope | `scope add`, then confirm |
| `/critic` fails | `/check-llm`, and an `agent_report.md` or `report_draft.md` |
| graph is empty | Reindex, then `/graph show example.com --min-score 40` |
| program weights missing | `/program set example-web`, then reindex |
| check-llm connection refused | From a VM, set `--base-url` to the Windows host IP, not the VM IP |
| cloud auth error | Export the provider key, then `python recon.py agents check-llm` |
| shell has no matches | `pip install prompt_toolkit` and use a real terminal |
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
python recon.py shell
```

```text
> /notable example.com
> /inbox example.com
> /graph show example.com
> /report example.com
```
