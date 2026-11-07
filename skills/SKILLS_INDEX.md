# reconkit Agent Skills Index (v3.0 skill suite)

Compiled from patterns in local clones under `git_skills/`
(Bug-Bounty-Agents, bughunter-ai, claude-bug-bounty, Claude-BugHunter)
and adapted to **reconkit** (scope gate, modules, prove, findings index).

Skills apply to **local Ollama and cloud** LLMs the same way. `src/agents/skills.py`
reads `skills/<name>/SKILL.md` and attaches that file to the call.

## Design goals (better than source packs)

| Source weakness | Our approach |
|-----------------|--------------|
| 40+ loose personas, no shared memory | One pack, role-routed injection, shared confidence model |
| Heavy payload/wordlist skills | Methodology + reconkit tools only (no spray/webshell packs) |
| Parallel agent thrash on weak hardware | Batch <=3 modules, kill-fast, progressive skill load |
| "Exploit" = free bash | **Confidence tiers** + safe prove + PoC templates for humans |
| High FP -> wasted LLM turns | **7-gate eval** before escalate / report / PoC write |

## Skills

| Skill | Role | When loaded |
|-------|------|-------------|
| `reconkit-bug-bounty` | planner | Core recon pipeline + rules |
| `reconkit-efficiency` | planner | Max output per step on local/cloud LLM |
| `reconkit-fp-eval` | analyst, critic, review, prove | Kill false positives fast |
| `reconkit-exploit-prove` | analyst, prove path | Authorized PoC writing + prove mapping |
| `reconkit-triage-gate` | analyst, critic | Pre-report 7-question + N/A lists |

### On-demand vuln-class skill files (one per call)

Loaded only when a finished module or the current text matches:

| Skill | Module triggers | Keyword / context triggers |
|-------|-----------------|----------------------------|
| `reconkit-vuln-idor` | `params`, `crawl`, `apis` | idor, bola, user_id, userid, account_id, order_id, `/users/`, `/api/v`, uuid |
| `reconkit-vuln-jwt` | `js`, `jsintel` | jwt, eyJ, bearer, access_token, id_token, refresh_token |
| `reconkit-vuln-graphql` | `crawl`, `graphql`, `apis` | graphql, `__schema`, introspection, `/graphql`, mutation |
| `reconkit-vuln-ssrf` | `ssrf_ssti`, `cloud`, `nuclei` | ssrf, webhook, callback, 169.254, metadata, oast, collaborator |
| `reconkit-vuln-xss` | `xss` | xss, dalfox, kxss, reflected, dom xss |
| `reconkit-vuln-sqli` | `sqli` | sqli, sql injection, boolean-based, error-based |
| `reconkit-vuln-takeover` | `dns`, `nuclei`, `takeover_plus` | takeover, cname, dangling, nxdomain, herokuapp, github.io |
| `reconkit-vuln-secrets` | `js`, `jsintel`, `cloud`, `gitrecon` | secret, AKIA, aws_key, api_key, private key, `-----BEGIN` |

**Example:** after the `xss` module finishes, the next planner call can attach
`skills/reconkit-vuln-xss/SKILL.md`. The default cap is **one** file
(`RECON_AGENT_SKILL_SURFACE`).

## Env

```bash
# default: load full pack by role
export RECON_AGENT_SKILL=reconkit-bug-bounty

# disable all skill injection
export RECON_AGENT_SKILL=off

# optional: comma list of extra skills always merged
export RECON_AGENT_SKILL_EXTRA=reconkit-fp-eval,reconkit-efficiency

# char budget for the skill files attached to one call
export RECON_AGENT_SKILL_MAX=8000

# vuln skill files per call (0-3). Default is 1.
export RECON_AGENT_SKILL_SURFACE=1
```

## Confidence model (shared)

```
C0  noise / tool artifact only
C1  candidate (scanner hit, no retest)
C2  reflected/reproduced with canary (reconkit prove)
C3  impact demonstrated (cross-user data, internal content, ATO chain)
C4  report-ready (gates pass + evidence bundle)
```

Never claim C3/C4 from nuclei alone. Escalate tools only when C improves.

### Mapping to reconkit commands

| Tier | Typical reconkit action |
|------|-------------------------|
| C0 | Drop; do not queue prove |
| C1 | `/findings reindex` -> `/prove queue` or manual |
| C2 | `/prove run` status `confirmed` |
| C3 | Human impact notes under program RoE |
| C4 | `/critic` + `/report` + submit |

## Pipeline (max efficiency)

```
scope -> recon (ordered modules) -> index/score
     -> fp-eval (C0/C1 filter)
     -> prove safe (C2)
     -> exploit-prove PoC draft (human/HITL for C3)
     -> triage-gate -> report
```

### Copy-paste example

```bash
cd path/to/Reconkit

# Scope + LLM (local or cloud -- skills identical)
python recon.py scope add example.com
python recon.py agents config set --provider ollama \
  --base-url http://192.168.1.4:11434 --model qwen3:8b
# or: config set --provider xai --model grok-2-latest   (with XAI_API_KEY)

python recon.py agents          # inspect skill suite
python recon.py agents run --target example.com \
  --modules subdomains,dns,httpprobe,xss,nuclei --max-steps 8

python recon.py findings reindex
python recon.py prove queue --target example.com
python recon.py prove run --target example.com

# Shell report path
# /report example.com
# /critic example.com
# /prove list example.com
# /graph show example.com
```

## Role routing (implementation)

Source of truth: `src/agents/skills.py` -> `ROLE_SKILLS`, `MODULE_SURFACE`,
`SURFACE_SKILLS`. The default is one vuln file. `RECON_AGENT_SKILL_SURFACE` raises that to 3.

| Role | Skill files |
|------|-------------|
| planner | bug-bounty, efficiency, plus one matching vuln file |
| specialist | bug-bounty, plus one matching vuln file |
| analyst | fp-eval, triage-gate, exploit-prove, plus one matching vuln file |
| critic | fp-eval, triage-gate, plus one matching vuln file |
| review | fp-eval, plus one vuln file for that phase |
| prove | fp-eval, exploit-prove, plus one matching vuln file |

Tool modules do not call the model. The planner call is the decision. The analyst call is the report. `--review` writes one note per phase from the review files above.

## Hunting prompts (verbatim)

`skills/bug-bounty-hunting-prompts/` keeps `ADAPTATION.md` and the phase files
that match this recon project. The loader appends each phase file in full.
`RECON_AGENT_SKILL_MAX` does not cut it. `RECON_AGENT_HUNT_PHASE=off` skips the
pack. A comma list of phase filenames replaces the role default.

| Call | Phase file |
|------|------------|
| planner | `phase-00-recon.md` |
| planner, after crawl / js / screenshots | `phase-04a-scope.md`, then `phase-00-recon.md` |
| analyst | `phase-06-triage.md` |
| critic | `phase-09-triage-gate.md` |
| review | `phase-06-triage.md` |
| review of crawl / js / screenshots | `phase-04a-scope.md`, then `phase-06-triage.md` |

`ADAPTATION.md` is attached with whichever phase file the call loads.
Prove and the tool step do not load a hunt phase.

Pre-eval (no LLM tokens): `src/agents/eval.py` before analyst report.

## See also

- **[README.md](README.md)** -- overview + design principles  
- **[USAGE.md](../USAGE.md#11-agent-skills)** -- skill usage examples  
- **[AGENTS.md](../AGENTS.md)** -- quick start  
