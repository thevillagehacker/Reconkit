---
name: reconkit-triage-gate
description: >
  Pre-report 7-question gate and pre-submission checks for bug bounty reports.
  Use before finalizing agent_report or report_draft. Kills N/A findings; saves
  reputation and LLM time. Adapted from claude-bug-bounty triage-validation for reconkit.
---

# Pre-report triage gate

One wrong answer = **do not submit** that finding. Mark INFORMATIONAL or drop.

## 7 questions (in order)

### Q1 — Attacker path now?
Can you write:

1. Setup (account?)  
2. **Exact** HTTP request  
3. Result (read/modify what?)  
4. Impact (real-world)  
5. Cost (time/$0?)  

No step 2 → **KILL**.

### Q2 — Program pays for this impact?
If known out-of-scope type → **KILL**.

### Q3 — Root cause on in-scope asset?
reconkit scope + not pure third-party → else **KILL**.

### Q4 — Needs unrealistic privilege?
“Already admin” → **KILL**.

### Q5 — Intended / documented?
Known design → **KILL**.

### Q6 — Impact beyond technical possibility?
alert(domain) only / DNS-only SSRF → downgrade or kill.

### Q7 — Known-invalid class?
See never-submit list in `reconkit-fp-eval` skill.

### Q8 — Identity (auth bugs)
For IDOR/auth: own vs other user; anon vs auth. Blank → unproven.

## 4 pre-submission gates

| Gate | Check |
|------|--------|
| 0 Reality | Real HTTP/tool proof, in scope, reproducible |
| 1 Impact | Clear “what attacker gains” |
| 2 Dedupe | Not known disclosed / changelog |
| 3 Quality | Title formula, steps, evidence, remediation |

## Title formula

```
[Bug Class] in [Endpoint/Asset] allows [actor] to [impact]
```

## Severity honesty

Overclaiming burns trust. Prefer Medium solid over Critical theoretical.

## reconkit report integration

In `agent_report.md` section 3, only list findings that pass Q1–Q3 at minimum.
Attach prove status when C2+.
Recommend `/prove` and `/graph` for remaining C1.
