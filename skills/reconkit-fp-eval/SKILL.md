---
name: reconkit-fp-eval
description: >
  False-positive evaluation for reconkit findings and prove results. Use before
  escalating modules, writing PoCs, or reporting. Kill-fast rules, confidence
  tiers C0-C4, nuclei/XSS/SSRF/SQLi trap classes. Reduces wasted LLM and tool effort.
---

# False-positive evaluation (kill-fast)

Inspired by claude-bug-bounty triage-validation + Bug-Bounty-Agents poc-validator,
rewired for reconkit artifacts and **local LLM cost**.

## Confidence tiers (required labels)

| Tier | Meaning | Action |
|------|---------|--------|
| **C0** | Noise / cosmetic | Drop from report; do not prove |
| **C1** | Scanner candidate | Optional prove; no severity claim |
| **C2** | Canary re-confirmed | Safe prove pass; still not full impact |
| **C3** | Impact shown | Cross-account / internal data / ATO path |
| **C4** | Report-ready | All gates pass + evidence |

**Rule:** Never promote C1→C3 without a validation step.

## Instant kill (C0) — never spend another step

If finding matches, classify C0 and move on:

- Security headers only (CSP/HSTS missing)
- SPF/DKIM/DMARC only
- GraphQL introspection alone
- Version/banner without working impact
- Self-XSS only
- Logout CSRF / concurrent sessions alone
- Mixed content / weak cipher alone
- Cookie flags alone without theft path
- Nuclei **info** template only
- Open redirect with **no** token/OAuth chain
- SSRF **DNS-only** OAST with no HTTP body/data
- CORS `*` without credentialed PII proof
- “Admin can do admin things”
- Own-account IDOR only (attacker == victim)

## Conditional (needs chain) — hold at C1 until chained

| Hit | Needs |
|-----|-------|
| Open redirect | OAuth/token theft chain |
| Clickjacking | Sensitive state-changing action |
| Host header | Password-reset poisoning proof |
| SSRF DNS | Internal HTTP data or metadata content |
| Takeover CNAME | Fingerprint + claimability note (human) |
| Reflected XSS | Context allows script (not only encoded) |

## reconkit-specific FP traps

| Source | Trap | Eval |
|--------|------|------|
| dalfox/kxss | Reflection ≠ executable XSS | Check prove `xss_reflect` context; CSP |
| sqli canary | Error string ≠ data SQLi | Need boolean/time or data; policy may block |
| nuclei | Template match stale | `nuclei_recheck`; version may be patched |
| js secrets | Dummy/test keys | Format + liveness unknown → C1 |
| ssti `49` | Coincidence | Confirm raw canary absent |
| cloud list | Public intentional bucket | Business context |

## LLM evaluation protocol (cheap)

For each top finding (max 5 per wave), answer in **one line each**:

```
ID: ...
Tier: C0|C1|C2|C3
Why: ≤15 words
Next: drop | prove:<technique> | manual | chain:<note>
```

If tier unclear → **C1**, not C3.

## Before any “exploit write”

Must pass:

1. In scope (reconkit scope file)  
2. Tier ≥ C1  
3. Not on instant-kill list  
4. Reproducible request sketch exists (method + URL + param)  
5. Impact sentence is concrete (not “could potentially”)  

Fail any → do not write PoC; recommend more recon or drop.
