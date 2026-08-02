# reconkit skill suite

Agent Skills ([agentskills.io](https://agentskills.io) format) for **maximum
efficiency** on local **and cloud** LLMs: less noise, fewer false positives,
structured PoC promotion â€” without shipping weaponized exploit packs.

Works with every provider supported by `agents/llm.py` (Ollama, Grok, Claude,
Gemini/Gemma, OpenAI, OpenRouter, Groq, …). Skills are text injected into system
prompts â€” they do not call the network themselves.

## Research inputs (local clones)

| Clone (`git_skills/`) | Borrowed | Left out |
|----------------------|----------|----------|
| **Bug-Bounty-Agents** | Scope gates, OPSEC QUIET/MODERATE/LOUD, safe PoC rules | AD/wireless/phishing free-for-all personas |
| **bughunter-ai** | Phased hunt, hypothesis priority, chain thinking, severity modes | sqlmap/ffuf thrash defaults, voice hooks |
| **claude-bug-bounty** | 7-question gate, N/A lists, CVSS honesty, kill-fast | Spray/credential-attack skill packs |
| **Claude-BugHunter** | Validate-before-report culture, eval mindset | Full autonomous multi-harness runtime |

Clones are **gitignored research** only. Runtime skills are the packs below.

## Our suite (better fit for reconkit)

| Skill | Job |
|-------|-----|
| `reconkit-bug-bounty` | Master rules + module pipeline |
| `reconkit-efficiency` | Hardware/token budgets, â‰¤3 modules/step |
| `reconkit-fp-eval` | C0–C4 tiers, instant kill FP list |
| `reconkit-exploit-prove` | Canary PoCs + map to `/prove` techniques |
| `reconkit-triage-gate` | Pre-report gates (save N/A ratio) |
| `reconkit-vuln-*` | On-demand: idor, jwt, graphql, ssrf, xss, sqli, takeover, secrets |

See **[SKILLS_INDEX.md](SKILLS_INDEX.md)** for the shared confidence model and
full trigger tables.

Surface mini-skills load only when the current modules/context match (e.g. `xss`
module → `reconkit-vuln-xss`), capped at **3 per turn** for efficiency.

## How agents load skills

```text
planner     → bug-bounty + efficiency + fp-eval
specialist  → bug-bounty + fp-eval  (+ surface mini-skills)
analyst     → bug-bounty + fp-eval + exploit-prove + triage-gate  (+ surface)
critic      → fp-eval + triage-gate + exploit-prove
prove path  → fp-eval + exploit-prove (methodology; runtime is still /prove)
```

`agents/skills.py` injects by role with a char budget (`RECON_AGENT_SKILL_MAX`).

Zero-token pre-eval: `agents/eval.py` runs heuristics before analyst LLM.

## Commands & examples

### Inspect wiring

```bash
cd path/to/Reconkit
python recon_agents.py agents
# → primary skill path
# → suite by role (planner / specialist / analyst / critic / prove)
# → surface: (on-demand) reconkit-vuln-...
# → index: skills/SKILLS_INDEX.md
```

### Default hunt (skills on)

```bash
python recon_agents.py check-llm
python recon_agents.py run --target example.com --dry-run
python recon_agents.py run --target example.com --max-steps 8
# skills inject automatically into planner/specialist/analyst
```

```text
/check-llm
/agents
/agent example.com --max-steps 8
```

### Surface mini-skill focus

```bash
# XSS module → unlocks reconkit-vuln-xss (count toward max 3 surface skills)
python recon_agents.py run --target example.com --modules xss --max-steps 4

# JS → secrets + jwt candidates
python recon_agents.py run --target example.com --modules crawl,js --max-steps 4

# After tools write files:
python reconkit.py findings reindex
python recon_prove.py run --target example.com --technique xss_reflect
```

### Disable or tune

```bash
# Disable all skill injection
export RECON_AGENT_SKILL=off
python recon_agents.py run --target example.com --max-steps 4

# Default primary
export RECON_AGENT_SKILL=reconkit-bug-bounty

# Always merge an extra pack
export RECON_AGENT_SKILL_EXTRA=reconkit-efficiency

# Smaller budget for tiny local models (e.g. 7B)
export RECON_AGENT_SKILL_MAX=8000

# Larger budget for cloud Sonnet / Grok
export RECON_AGENT_SKILL_MAX=20000
```

### Cloud + skills (same packs)

```bash
export XAI_API_KEY=xai-...
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py check-llm
python recon_agents.py run --target example.com --max-steps 8
# C0–C4 rules still apply â€” skills are provider-agnostic
```

### End-to-end confidence ladder

```text
1. /agent example.com --modules nuclei,xss
   → planner/specialist use fp-eval; surface may load vuln-xss / takeover
2. /findings reindex
   → C1 candidates scored in index
3. /prove run example.com
   → C2 if canary confirms
4. Write PoC from exploit-prove template (human)
   → still C2 until impact shown
5. Demonstrate impact under RoE (human HITL)
   → C3
6. /critic example.com  (triage-gate + fp-eval)
   → C4-ready report language
7. /report example.com + dashboard Proofs tab
```

## Design principles

1. **Kill FPs before tools** â€” evaluation costs tokens once; bad modules cost minutes.  
2. **Prove before â€œexploit writeâ€** â€” C2 automated canaries, then human C3 impact.  
3. **No payload zoos in-repo** â€” methodology > 10k XSS strings for local agents.  
4. **reconkit-native** â€” modules, prove, findings index, graph handoffs only.  
5. **Provider-agnostic** â€” same skills for Ollama and cloud.  

## Layout

```text
skills/
  README.md                 # this file
  SKILLS_INDEX.md           # confidence model + triggers
  reconkit-bug-bounty/
    SKILL.md
    references/             # deeper methodology notes
  reconkit-efficiency/SKILL.md
  reconkit-fp-eval/SKILL.md
  reconkit-exploit-prove/SKILL.md
  reconkit-triage-gate/SKILL.md
  reconkit-vuln-idor/SKILL.md
  reconkit-vuln-jwt/SKILL.md
  reconkit-vuln-graphql/SKILL.md
  reconkit-vuln-ssrf/SKILL.md
  reconkit-vuln-xss/SKILL.md
  reconkit-vuln-sqli/SKILL.md
  reconkit-vuln-takeover/SKILL.md
  reconkit-vuln-secrets/SKILL.md
```

Loader: `agents/skills.py` Â· pre-eval: `agents/eval.py`  
User docs: **USAGE.md Â§21** Â· **OPERATIONS.md Â§14** Â· **WORKFLOW.md Phase M**.
