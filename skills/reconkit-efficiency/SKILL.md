---
name: reconkit-efficiency
description: >
  Maximize reconkit agent output under limited CPU/RAM/GPU (local Ollama).
  Use for planner step budgeting, batch sizing, early stop, and reducing wasted
  LLM tokens and tool runs. Prefer high-signal modules; avoid parallel thrash.
---

# reconkit efficiency (local LLM / hardware)

Assume **one** local model, modest VRAM, and recon tools competing for CPU.

## Hard budgets

| Resource | Budget |
|----------|--------|
| Modules per planner step | **1–3 max** |
| Planner reasoning | ≤ 40 words in `reasoning` |
| Specialist summary | 4–8 bullets, ≤ 200 words |
| Context | Prefer counts + top 3 samples, never dump full files |
| Max empty retries | 1 re-try then skip module class |
| Screenshots | Last / optional only |

## Decision cost model

Pick the step with highest **Expected Signal / Cost**:

```
Score ≈ (impact_if_true × confidence_gain) / (time + noise + tokens)
```

| Action | Relative cost | When worth it |
|--------|---------------|---------------|
| subdomains | medium | First step only if missing |
| dns+httpprobe | medium | After subdomains |
| crawl | medium-high | After alive hosts |
| js/params | medium | After urls |
| nuclei (critical+high) | high | After alive; prefer over blind xss |
| xss/sqli/ssrf | high | Only if urls/params exist |
| content fuzz | high | Cap hosts; after tech fingerprint |
| screenshots | medium | End only |

## Early-stop rules

Set `done=true` when any hold:

1. Core chain complete: `subdomains` + `httpprobe` + (`crawl` or no alive) + (`nuclei` or `js`)
2. Remaining only low-ROI (e.g. screenshots) and max_steps tight
3. Two consecutive empty high-cost modules and tools look broken → recommend `/doctor`, stop looping

## Token hygiene for Ollama

- System skill: keep loaded; do not re-paste full tips every turn
- User message: COMPLETED/REMAINING lists, not full history dumps
- No multi-page markdown in planner output — **JSON only**
- Temperature 0.1–0.2 for plan/eval

## Parallelism (reconkit reality)

reconkit runs modules **sequentially** in a step. Do not plan 8 modules “in parallel” — the planner only schedules the next batch. Prefer one coherent batch owned by one specialist agent.

## Noise / OPSEC tags (from Bug-Bounty-Agents)

Tag planned work mentally:

- **QUIET**: passive CT / DNS read  
- **MODERATE**: httpx, crawl, nuclei moderate  
- **LOUD**: ffuf content, aggressive vuln  

Under bounty RoE prefer MODERATE before LOUD unless high-value signal exists.
