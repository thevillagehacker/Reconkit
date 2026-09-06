# reconkit roadmap (v3.0.0)

**Docs:** [USAGE.md](USAGE.md)  /  [WORKFLOW.md](WORKFLOW.md)  /  [OPERATIONS.md](OPERATIONS.md)  /  [AGENTS.md](AGENTS.md)  /  [skills/](skills/)

v3.0.0 = v2.1.0 + **program profiles**, **prove v2**, **attack-path graph**, **dashboard Graph/Insights**, **multi-provider LLMs**, **agent skill suite** (core + on-demand mini-skills).

## Done in 2.2

| Item | Status |
|------|--------|
| Program profiles (`config/programs/`, `/program`) | [x] |
| Weighted scoring by bounty category | [x] |
| Prove v2: XSS context classification | [x] |
| Prove v2: OAST SSRF (`oast_base_url`) | [x] |
| Prove v2: optional `sqli_boolean` (off by default) | [x] |
| Attack-path graph builder (`graph/`) | [x] |
| Dashboard **Graph** tab (force layout) | [x] |
| Dashboard **Insights** charts | [x] |
| API `/api/graph`, `/api/stats/charts`, `/api/program` | [x] |
| Dashboard typography (Helvetica Neue / Inter) + JetBrains Mono console | [x] |
| **Multi-provider LLM** (Ollama + xAI Grok, Anthropic Claude, Google Gemini/Gemma, OpenAI, OpenRouter, Groq, ...) | [x] |
| `recon_agents.py providers` + cloud config templates | [x] |
| **Agent skill suite** (efficiency + FP eval + exploit-prove + triage) | [x] |
| **On-demand vuln mini-skills** (`reconkit-vuln-*`, max 3/turn) | [x] |
| Heuristic pre-eval `agents/eval.py` (C0-C4) | [x] |
| Exhaustive docs: OPERATIONS / WORKFLOW / USAGE / skills | [x] |

## Done in hunter extras

See **[HUNTER.md](HUNTER.md)**.

| Item | Status |
|------|--------|
| Auth session (`/session`, cookie A/B, httpx/prove headers) | [x] |
| Multi-scope `--scope-all` | [x] |
| JS intel / API harvest / 403 bypass / takeover+ | [x] |
| Ports (naabu) / permute / well-known / gf extras | [x] |
| Scoped OSINT + git/trufflehog | [x] |
| CORS / JWT / GraphQL / redirect / IDOR prove | [x] |
| HAR import, evidence ZIP, target wordlist, `--resume` | [x] |
| Hunter inbox (`/inbox`  /  dashboard **INBOX**  /  `/api/inbox`) | [x] |
| SQLite findings query path (`findings/db.py`) | [x] |

## Still open (future)

- Hypothesis agent + Kanban  
- Lab profile (`max_risk_class: intrusive`)  
- Deeper GraphQL introspection pack (off by default; RoE gated)  
- Optional `/eval` shell command surface for pre-eval dumps  

---

**Principle:** recon finds  /  programs prioritize  /  prove confirms safely  /  graph explains  /  skills kill FPs  /  cloud or local LLM.
