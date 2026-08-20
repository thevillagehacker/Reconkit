# reconkit roadmap (v3.0.0)

**Docs:** [USAGE.md](USAGE.md) Â· [WORKFLOW.md](WORKFLOW.md) Â· [OPERATIONS.md](OPERATIONS.md) Â· [AGENTS.md](AGENTS.md) Â· [skills/](skills/)

v3.0.0 = v2.1.0 + **program profiles**, **prove v2**, **attack-path graph**, **dashboard Graph/Insights**, **multi-provider LLMs**, **agent skill suite** (core + on-demand mini-skills).

## Done in 2.2

| Item | Status |
|------|--------|
| Program profiles (`config/programs/`, `/program`) | âœ… |
| Weighted scoring by bounty category | âœ… |
| Prove v2: XSS context classification | âœ… |
| Prove v2: OAST SSRF (`oast_base_url`) | âœ… |
| Prove v2: optional `sqli_boolean` (off by default) | âœ… |
| Attack-path graph builder (`graph/`) | âœ… |
| Dashboard **Graph** tab (force layout) | âœ… |
| Dashboard **Insights** charts | âœ… |
| API `/api/graph`, `/api/stats/charts`, `/api/program` | âœ… |
| Dashboard typography (Helvetica Neue / Inter) + JetBrains Mono console | âœ… |
| **Multi-provider LLM** (Ollama + xAI Grok, Anthropic Claude, Google Gemini/Gemma, OpenAI, OpenRouter, Groq, …) | âœ… |
| `recon_agents.py providers` + cloud config templates | âœ… |
| **Agent skill suite** (efficiency + FP eval + exploit-prove + triage) | âœ… |
| **On-demand vuln mini-skills** (`reconkit-vuln-*`, max 3/turn) | âœ… |
| Heuristic pre-eval `agents/eval.py` (C0–C4) | âœ… |
| Exhaustive docs: OPERATIONS / WORKFLOW / USAGE / skills | âœ… |

## Done in hunter extras

See **[HUNTER.md](HUNTER.md)**.

| Item | Status |
|------|--------|
| Auth session (`/session`, cookie A/B, httpx/prove headers) | ✅ |
| Multi-scope `--scope-all` | ✅ |
| JS intel / API harvest / 403 bypass / takeover+ | ✅ |
| Ports (naabu) / permute / well-known / gf extras | ✅ |
| Scoped OSINT + git/trufflehog | ✅ |
| CORS / JWT / GraphQL / redirect / IDOR prove | ✅ |
| HAR import, evidence ZIP, target wordlist, `--resume` | ✅ |
| Hunter inbox (`/inbox` · dashboard **INBOX** · `/api/inbox`) | ✅ |
| SQLite findings query path (`findings/db.py`) | ✅ |

## Still open (future)

- Hypothesis agent + Kanban  
- Lab profile (`max_risk_class: intrusive`)  
- Deeper GraphQL introspection pack (off by default; RoE gated)  
- Optional `/eval` shell command surface for pre-eval dumps  

---

**Principle:** recon finds Â· programs prioritize Â· prove confirms safely Â· graph explains Â· skills kill FPs Â· cloud or local LLM.
