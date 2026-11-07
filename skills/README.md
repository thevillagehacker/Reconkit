# reconkit skill suite

Agent Skills ([agentskills.io](https://agentskills.io) format) for **maximum
efficiency** on local **and cloud** LLMs: less noise, fewer false positives,
structured PoC promotion -- without shipping weaponized exploit packs.

Works with every provider supported by `agents/llm.py` (Ollama, Grok, Claude,
Gemini/Gemma, OpenAI, OpenRouter, Groq, ...). `agents/skills.py` reads the
`SKILL.md` files and attaches the ones for that call. The files do not call
the network.

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
| `reconkit-efficiency` | Hardware/token budgets, <=3 modules/step |
| `reconkit-fp-eval` | C0-C4 tiers, instant kill FP list |
| `reconkit-exploit-prove` | Canary PoCs + map to `/prove` techniques |
| `reconkit-triage-gate` | Pre-report gates (save N/A ratio) |
| `reconkit-vuln-*` | On-demand: idor, jwt, graphql, ssrf, xss, sqli, takeover, secrets |

See **[SKILLS_INDEX.md](SKILLS_INDEX.md)** for the shared confidence model and
full trigger tables.

One vuln skill file is attached when the modules that already ran match it
(for example `xss` -> `reconkit-vuln-xss`). Set `RECON_AGENT_SKILL_SURFACE`
to `0`, `2`, or `3` if you want a different cap.

## How a model call loads skills

```text
planner   -> skills/reconkit-bug-bounty/SKILL.md
             skills/reconkit-efficiency/SKILL.md
             + one vuln file if a finished module matches
analyst   -> fp-eval + triage-gate + exploit-prove (+ one vuln file)
critic    -> fp-eval + triage-gate (+ one vuln file from the report text)
review    -> fp-eval (+ one vuln file for that phase)
prove     -> fp-eval + exploit-prove
```

The tool step itself does not call the model. File counts go to the next
planner call. `RECON_AGENT_SKILL_MAX` caps the attached reconkit skill text
(default 8000).

`skills/bug-bounty-hunting-prompts/` holds `ADAPTATION.md` and the phase files
this project uses. Those files are stored and attached unchanged. The char
budget does not cut them. See **SKILLS_INDEX.md** for which call loads which
phase. Set `RECON_AGENT_HUNT_PHASE=phase-00-recon` to force one file, or `off`
to skip the pack.

Zero-token pre-eval: `agents/eval.py` runs heuristics before the analyst.

## Commands & examples

### Inspect wiring

```bash
cd path/to/Reconkit
python recon_agents.py agents
# -> primary skill path
# -> suite by role (planner / specialist / analyst / critic / prove)
# -> surface: (on-demand) reconkit-vuln-...
# -> index: skills/SKILLS_INDEX.md
```

### Default hunt (skills on)

```bash
python recon_agents.py check-llm
python recon_agents.py run --target example.com --dry-run
python recon_agents.py run --target example.com --max-steps 8
# planner and analyst load the skill files for that call
```

```text
/check-llm
/agents
/agent example.com --max-steps 8
```

### Surface mini-skill focus

```bash
# a finished xss module attaches skills/reconkit-vuln-xss/SKILL.md
python recon_agents.py run --target example.com --modules xss --max-steps 4

# JS -> secrets + jwt candidates
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

# Default budget. Lower it for a small local model.
export RECON_AGENT_SKILL_MAX=8000

# Attach no vuln pack, or up to three, on a call that matches.
export RECON_AGENT_SKILL_SURFACE=1
```

### Cloud + skills (same packs)

```bash
export XAI_API_KEY=xai-...
python recon_agents.py config set --provider xai --model grok-2-latest
python recon_agents.py check-llm
python recon_agents.py run --target example.com --max-steps 8
# C0-C4 rules still apply -- skills are provider-agnostic
```

### End-to-end confidence ladder

```text
1. /agent example.com --modules nuclei,xss
   -> planner reads bug-bounty + efficiency; a finished xss module attaches vuln-xss
2. /findings reindex
   -> C1 candidates scored in index
3. /prove run example.com
   -> C2 if canary confirms
4. Write PoC from exploit-prove template (human)
   -> still C2 until impact shown
5. Demonstrate impact under RoE (human HITL)
   -> C3
6. /critic example.com  (triage-gate + fp-eval)
   -> C4-ready report language
7. /report example.com
   /prove list example.com
```

## Design principles

1. **Kill FPs before tools** -- evaluation costs tokens once; bad modules cost minutes.  
2. **Prove before "exploit write"** -- C2 automated canaries, then human C3 impact.  
3. **No payload zoos in-repo** -- methodology > 10k XSS strings for local agents.  
4. **reconkit-native** -- modules, prove, findings index, graph handoffs only.  
5. **Provider-agnostic** -- same skills for Ollama and cloud.  

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
  bug-bounty-hunting-prompts/
    ADAPTATION.md
    phases/phase-00-recon.md
    phases/phase-04a-scope.md
    phases/phase-06-triage.md
    phases/phase-09-triage-gate.md
```

Loader: `agents/skills.py`  /  pre-eval: `agents/eval.py`  
User docs: **[USAGE.md](../USAGE.md#11-agent-skills)**  /  **OPERATIONS.md section 14**  /  **WORKFLOW.md Phase M**  /  **[HUNTER.md](../HUNTER.md)**.
