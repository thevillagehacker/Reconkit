# Analyst report template (agent_report.md)

```markdown
# Agent recon report — {target}

## 1. Executive summary
- Scope: {target} (authorized)
- Depth: modules completed …
- Top risks: 3 bullets max (evidence-based)

## 2. Asset inventory
- Subdomains: count / notes
- Alive hosts: count / interesting titles
- URLs / params: counts
- Output dir: ~/.reconkit/output/{target}/

## 3. High-interest findings
### Takeover / DNS
- …

### Secrets / JS
- … (types only; redacted)

### Vuln candidates (nuclei / xss / sqli / ssrf / cloud)
- … each with source file hint

## 4. Suggested next steps (human)
1. /findings reindex && /notable
2. /prove queue && /prove run (safe validators)
3. /graph show — attack path
4. Manual review of … under program RoE
5. Do not treat candidates as confirmed exploits

## 5. Gaps / failures
- Empty stages, missing tools, skipped modules
```

Only include sections with real evidence.
