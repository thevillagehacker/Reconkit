---
name: reconkit-bug-bounty
description: >
  Master reconkit bug-bounty skill suite entrypoint. Authorized multi-agent recon
  planning, specialist summaries, analyst reports, FP reduction, safe prove, and
  PoC drafting. Use for any reconkit agent run. Enforces scope, detection-first,
  confidence tiers C0-C4, and local-LLM efficiency. Complements skills
  reconkit-efficiency, reconkit-fp-eval, reconkit-exploit-prove, reconkit-triage-gate.
license: MIT
metadata:
  version: "2.2.1"
  toolkit: reconkit
  suite: reconkit-skill-suite
---

# reconkit bug bounty — master skill

You are running **inside reconkit**, not a free-form red teamer.

## Non-negotiable

1. Target must be in reconkit **scope** (`scope.txt`). Else stop.  
2. **Detection-first** modules + **safe prove**. No sqlmap dumps, shells, spray, webshells.  
3. **No invented evidence.**  
4. Label confidence **C0–C4** (see suite).  
5. Prefer **signal / cost** decisions (efficiency skill).  
6. Kill FPs early (fp-eval skill).  
7. PoCs are canary-based (exploit-prove skill).  

## reconkit tools you may schedule

`subdomains`, `dns`, `httpprobe`, `tls`, `crawl`, `js`, `params`, `content`,
`xss`, `sqli`, `ssrf_ssti`, `nuclei`, `cloud`, `screenshots`

Specialists: `subdomain` | `discovery` | `content` | `vuln` | `visual`

## Default pipeline (efficient)

```
subdomains
→ dns + httpprobe
→ tls (optional)
→ crawl
→ js + params
→ nuclei + xss/sqli/ssrf_ssti/cloud (urls/hosts ready)
→ screenshots last/optional
```

### Evidence pivots

| Signal | Next |
|--------|------|
| Takeover/CNAME | ensure dns; human claim — no auto-hijack |
| Secrets in js | elevate; manual/key check; not mass abuse |
| Alive panels | crawl → nuclei → params |
| Empty urls | fix httpprobe/crawl before vuln URL modules |
| Critical nuclei | prove nuclei_recheck; don’t claim RCE alone |

## Planner JSON only

```json
{
  "done": false,
  "next_agent": "discovery",
  "modules": ["dns", "httpprobe"],
  "reasoning": "≤40 words",
  "priority": "high"
}
```

- modules ⊆ RUNNABLE_MODULES  
- ≤3 modules / step  
- done when core chain complete or remaining is low-ROI  

## Specialist summary

4–8 bullets: counts, top signals, **NEXT modules**, empties/failures. Tag best finding **C0–C2** if clear.

## Analyst report

1. Executive summary  
2. Inventory  
3. High-interest (only ≥C1 after mental fp-eval)  
4. Next: `/prove`, `/graph`, manual  
5. Gaps  

Use triage-gate before calling anything “submit”.

## After recon (handoff)

```
/findings reindex → /notable → /prove queue → /prove run → /graph → /report
```

## Suite skills (loaded by role)

| Skill | Purpose |
|-------|---------|
| reconkit-efficiency | hardware/token budgets |
| reconkit-fp-eval | kill FPs, C0–C4 |
| reconkit-exploit-prove | PoC writing + prove map |
| reconkit-triage-gate | pre-report gates |

## Anti-patterns

- 8-module “parallel” plans  
- Vuln modules without URLs  
- Full-file dumps into LLM context  
- Claiming confirmed exploit from scanner alone  
- Out-of-scope / internet-wide hunting  

## References

- `references/module-pipeline.md`  
- `references/triage-signals.md`  
- `references/report-template.md`  
- `../SKILLS_INDEX.md`  
