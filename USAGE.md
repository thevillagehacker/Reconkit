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
The older form `python recon.py run --target example.com` still works.

Other docs: [AGENTS.md](AGENTS.md), [HUNTER.md](HUNTER.md),
[config/CLOUD_LLM_SETUP.md](config/CLOUD_LLM_SETUP.md),
[skills/README.md](skills/README.md).

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
| Scan view | `python recon.py view example.com` |
| Quick playbook | `python recon.py playbook run quick --target example.com` |
| Full playbook | `python recon.py playbook run full --target example.com` |
| Playbook list | `python recon.py playbook list` |
| Notable scores | `python recon.py notable --target example.com` |
| Diff | `python recon.py diff --target example.com` |
| Report draft | `python recon.py report --target example.com` |
| Attack graph | `python recon.py graph show --target example.com` |
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
recorded in the note and the scan continues. Ctrl+C skips `reviews/summary.txt`.

Each result is written once. Per-source subdomain and crawl lists go to
`~/.reconkit/output/<target>/tools/<stage>/<tool>.txt` as that tool finishes,
and the merge file (`subdomains.txt`, `urls.txt`) is rebuilt from those lists.
A stage with one result writes that file at the output root (`alive.txt`,
`dns_records.txt`, `resolved.txt`, `tls_recon.json`, `wellknown.txt`) and keeps
the exit code in `tools/<stage>/<tool>.txt.rc`. On a terminal, one running
line stays in place. Each finished tool then prints one result row.

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

Reindex after a scan so scores, diffs, the graph, and prove see the new files.

```bash
python recon.py findings reindex
python recon.py findings example.com
python recon.py notable --target example.com --limit 40
python recon.py diff --target example.com
python recon.py report --target example.com
python recon.py report --target example.com --all
python recon.py inbox --target example.com
python recon.py eval --target example.com
python recon.py graph summary --target example.com
python recon.py graph show --target example.com --min-score 40
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
| `graph show` | Target, host, finding, and proof links. `--min-score 40` hides low scores. |

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

Cookies stay in `~/.reconkit/session.json`. HAR import keeps in-scope URLs and
can copy a Cookie into the session. `rate` stores stealth, normal, or
aggressive in the reconkit config. Stealth lowers concurrency and adds delay.
Aggressive is faster and still has to stay inside the program rules.
`set` stores a tool time cap. The new value applies the next time that tool
starts, including the next run. Amass accepts 30 to 900 seconds.

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
src/                 reconkit, prove, agents, findings, graph, hunter, programs
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
| findings look old | `python recon.py findings reindex` |
| diff wants two reindexes | Reindex once after each scan |
| notable is empty | Reindex. Rows under the score floor are hidden. |
| prove queue is empty | Reindex, then `python recon.py prove queue --target example.com --all` |
| prove says out of scope | `scope add`, then confirm |
| critic fails | `python recon.py agents check-llm`, and an `agent_report.md` or `report_draft.md` |
| graph is empty | Reindex, then `python recon.py graph show --target example.com --min-score 40` |
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
python recon.py graph show --target example.com
python recon.py report --target example.com
```
