# reconkit hunter extras

Authorized bug-bounty / VDP recon extras used by a hunter or OSE. Detection
and safe prove only — no sqlmap, shells, dumps, credential spray, or
internet-wide mass scan.

**Related:** [USAGE.md](USAGE.md) · [OPERATIONS.md](OPERATIONS.md) · [WORKFLOW.md](WORKFLOW.md)

Tiers below match how the extras were added: **use Tier 1 first**, then 2–4.

---

## Safety (unchanged)

- Scope gate on recon, prove, HAR import, and agents (`~/.reconkit/scope.txt`).
- Session cookies live in `~/.reconkit/session.json` (chmod 600, never commit).
- OSINT (Shodan/Censys) is constrained to **this hostname**, never internet-wide.
- GraphQL prove is `{__typename}` only (no schema dump).
- IDOR prove compares **your** two sessions; it does not pull other users' data.
- JWT prove decodes header/payload only (no secret cracking, no `alg=none` attack).

---

## Tier 1 — authenticated surface & high-signal extras

| Feature | How |
|---------|-----|
| Auth session (cookie A + headers) | `/session set --cookie "…" --header "Authorization: Bearer …"` |
| Multi-scope run | `/run --scope-all --modules subdomains,dns,httpprobe` |
| JS intel (maps, routes, lib versions) | module `jsintel` |
| API / OpenAPI / IDOR-shaped URLs | module `apis` |
| Extra takeover (package.json, CDN 404) | module `takeover_plus` |
| Tech-tagged nuclei pack | automatic inside `nuclei` when httpx tech matches |
| Safe 401/403 header/path probes | module `bypass403` (no password spray) |

```text
/session set --cookie "sid=abc"
/run example.com --modules httpprobe,crawl,js,jsintel,apis,bypass403
/playbook run auth-surface example.com
```

```bash
python reconkit.py session set --cookie "sid=abc" --header "Authorization: Bearer …"
python reconkit.py run --target example.com --modules jsintel,apis,bypass403,takeover_plus
python reconkit.py run --scope-all --modules subdomains,dns,httpprobe
```

---

## Tier 2 — more surface, still in-scope

| Feature | How |
|---------|-----|
| Capped DNS permutations | module `permute` (alterx/dnsgen, then dnsx) |
| In-scope port probe | module `ports` (naabu connect-scan + httpx) |
| gf extras (redirect / lfi / interestingparams) | module `gfextra` |
| Well-known / robots / security.txt | module `wellknown` |
| Scoped Shodan/Censys | module `osint` (hostname query only) |
| GitHub/GitLab URLs + optional trufflehog | module `gitrecon` (one public repo) |
| WAF backoff | httpprobe writes `waf_detected.txt`; Cloudflare → `/rate stealth` |

```text
/playbook run hunter example.com
/playbook run ports-hint example.com
/run example.com --modules permute,ports,wellknown,gfextra,osint,gitrecon
```

---

## Tier 3 — safe prove extras (C1 → C2)

Set `oast_base_url` in `config/exploit_policy.json` for redirect/SSRF canaries.

| Technique | Input | Action |
|-----------|--------|--------|
| `jwt_inspect` | JWT-shaped token in evidence | Decode header/payload only |
| `cors_origin` | CORS candidate | Origin canary; confirm ACAO + credentials |
| `graphql_typename` | GraphQL URL | POST `{__typename}` only |
| `redirect_canary` | Redirect candidate | Bounce to OAST or `.invalid` |
| `idor_session_diff` | IDOR-shaped URL | GET with cookie A vs cookie B |

Matching recon modules: `redirect`, `cors`, `graphql` (detection), then `/prove`.

```text
/session set --cookie "userA=…" --cookie-b "userB=…"
/findings reindex
/prove queue example.com
/prove run example.com --technique cors_origin
/prove run example.com --technique idor_session_diff
```

```bash
python recon_prove.py run --target example.com --technique jwt_inspect
python recon_prove.py run --target example.com --technique graphql_typename
python recon_prove.py run --target example.com --technique redirect_canary
```

---

## Tier 4 — hunt ops (HAR, resume, evidence, inbox)

| Feature | How |
|---------|-----|
| HAR import | `/har import capture.har example.com` — in-scope URLs → `urls.txt`; Cookie → session |
| Target wordlist | `/wordlist-target example.com` → `wordlist_target.txt` |
| Resume a partial run | `/run example.com --resume` (skip stages whose output exists; `--force` to redo) |
| Evidence ZIP | `/evidence example.com` → `evidence_<target>_….zip` |
| Notify | if `notify` CLI is installed, a C1+ vuln count is sent at end of a successful run |
| Hunter inbox | `/inbox` or dashboard **INBOX** tab (`GET /api/inbox`) |

```text
/har import ~/Downloads/app.har example.com
/run example.com --resume --modules crawl,js,jsintel,apis
/findings reindex
/inbox example.com
/evidence example.com
/dashboard          # SCAN · FINDINGS · INBOX · PROOFS · GRAPH · INSIGHTS
```

```bash
python reconkit.py har --target example.com --file capture.har
python reconkit.py run --target example.com --resume
python reconkit.py wordlist-target --target example.com
python reconkit.py evidence --target example.com
curl -s "http://127.0.0.1:8787/api/inbox?target=example.com"
```

---

## New modules (pipeline order)

```
subdomains → permute → dns → ports → httpprobe → tls → wellknown
         → crawl → js → jsintel → params → apis → content → bypass403 → gfextra
         → xss → sqli → ssrf_ssti → redirect → cors → graphql
         → nuclei → cloud → takeover_plus → osint → gitrecon → screenshots
```

List descriptions anytime: `/modules` or `python reconkit.py modules`.

Playbooks: `auth-surface`, `hunter`, `api-surface`, `js-deep`, `ports-hint`,
`content-light`, `prove-prep`, `vuln-pass`, `takeover-first`.

---

## Output files (hunter extras)

Under `~/.reconkit/output/<target>/`:

| File | Module |
|------|--------|
| `permute_resolved.txt` | permute |
| `ports.txt`, `ports_http.txt` | ports |
| `waf_detected.txt` | httpprobe |
| `wellknown.txt` | wellknown |
| `js_intel.json`, `api_paths.txt` | jsintel |
| `api_urls.txt`, `idor_candidates.txt` | apis |
| `bypass403.txt` | bypass403 |
| `redirect_candidates.txt`, `lfi_candidates.txt`, `interesting_params.txt` | gfextra |
| `redirect_hits.txt` | redirect |
| `cors_candidates.txt` | cors |
| `graphql_endpoints.txt` | graphql |
| `nuclei_tech.txt` | nuclei (tech tags) |
| `takeover_plus.txt` | takeover_plus |
| `osint.txt` | osint |
| `git_urls.txt`, `trufflehog.jsonl` | gitrecon |
| `wordlist_target.txt` | `/wordlist-target` |
| `evidence_*.zip` | `/evidence` |

Session file: `~/.reconkit/session.json` (not under output/).
