# reconkit Agent Skills Index (v3.0 skill suite)

Compiled from patterns in local clones under `git_skills/`
(Bug-Bounty-Agents, bughunter-ai, claude-bug-bounty, Claude-BugHunter)
and adapted to **reconkit** (scope gate, modules, prove, findings index).

Skills apply to **local Ollama and cloud** LLMs the same way (prompt injection
via `agents/skills.py`).

## Design goals (better than source packs)

| Source weakness | Our approach |
|-----------------|--------------|
| 40+ loose personas, no shared memory | One pack, role-routed injection, shared confidence model |
| Heavy payload/wordlist skills | Methodology + reconkit tools only (no spray/webshell packs) |
| Parallel agent thrash on weak hardware | Batch â‰¤3 modules, kill-fast, progressive skill load |
| â€œExploitâ€ = free bash | **Confidence tiers** + safe prove + PoC templates for humans |
| High FP → wasted LLM turns | **7-gate eval** before escalate / report / PoC write |

## Skills

| Skill | Role | When loaded |
|-------|------|-------------|
| `reconkit-bug-bounty` | planner, specialist, analyst | Core recon pipeline + rules |
| `reconkit-efficiency` | planner | Max output per step on local/cloud LLM |
| `reconkit-fp-eval` | planner, specialist, analyst, critic, prove | Kill false positives fast |
| `reconkit-exploit-prove` | analyst, critic, prove path | Authorized PoC writing + prove mapping |
| `reconkit-triage-gate` | analyst, critic | Pre-report 7-question + N/A lists |

### On-demand vuln-class mini-skills (max 3 / turn)

Loaded only when modules/context match (saves tokens):

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

**Example:** run with `--modules xss` → surface set may include `reconkit-vuln-xss`
(and up to two more if other signals match). Cap is always **3**.

## Env

```bash
# default: load full pack by role
export RECON_AGENT_SKILL=reconkit-bug-bounty

# disable all skill injection
export RECON_AGENT_SKILL=off

# optional: comma list of extra skills always merged
export RECON_AGENT_SKILL_EXTRA=reconkit-fp-eval,reconkit-efficiency

# char budget for all injected skill text
export RECON_AGENT_SKILL_MAX=14000   # try 8000 on small local models
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
| C1 | `/findings reindex` → `/prove queue` or manual |
| C2 | `/prove run` status `confirmed` |
| C3 | Human impact notes under program RoE |
| C4 | `/critic` + `/report` + submit |

## Pipeline (max efficiency)

```
scope → recon (ordered modules) → index/score
     → fp-eval (C0/C1 filter)
     → prove safe (C2)
     → exploit-prove PoC draft (human/HITL for C3)
     → triage-gate → report
```

### Copy-paste example

```bash
cd path/to/Reconkit

# Scope + LLM (local or cloud â€” skills identical)
python reconkit.py scope add example.com
python recon_agents.py config set --provider ollama \
  --base-url http://192.168.1.4:11434 --model qwen3:8b
# or: config set --provider xai --model grok-2-latest   (with XAI_API_KEY)

python recon_agents.py agents          # inspect skill suite
python recon_agents.py run --target example.com \
  --modules subdomains,dns,httpprobe,xss,nuclei --max-steps 8

python reconkit.py findings reindex
python recon_prove.py queue --target example.com
python recon_prove.py run --target example.com

# Shell report path
# /report example.com
# /critic example.com
# /dashboard   → Proofs + Graph + Insights
```

## Role routing (implementation)

Source of truth: `agents/skills.py` → `ROLE_SKILLS`, `MODULE_SURFACE`,
`SURFACE_SKILLS`, `MAX_SURFACE_SKILLS = 3`.

| Role | Core skills |
|------|-------------|
| planner | bug-bounty, efficiency, fp-eval |
| specialist | bug-bounty, fp-eval |
| analyst | bug-bounty, fp-eval, exploit-prove, triage-gate |
| critic | fp-eval, triage-gate, exploit-prove |
| prove | fp-eval, exploit-prove |

Pre-eval (no LLM tokens): `agents/eval.py` before analyst report.

## See also

- **[README.md](README.md)** â€” overview + design principles  
- **[USAGE.md Â§21](../USAGE.md)** â€” full usage examples  
- **[OPERATIONS.md Â§14](../OPERATIONS.md)** â€” CLI catalog  
- **[WORKFLOW.md Phase M](../WORKFLOW.md)** â€” ordered hunt phase  
- **[AGENTS.md](../AGENTS.md)** â€” quick start  
