# reconkit hunter extras

Authorized bug-bounty / VDP recon extras used by a hunter or OSE. Detection
and safe prove only -- no sqlmap, shells, dumps, credential spray, or
internet-wide mass scan.

**Related:** [USAGE.md](USAGE.md)  /  [AGENTS.md](AGENTS.md)

Tiers below match how the extras were added: **use Tier 1 first**, then 2-4.

---

## Safety (unchanged)

- Scope gate on recon, prove, HAR import, and agents (`~/.reconkit/scope.txt`).
- Session cookies live in `~/.reconkit/session.json` (chmod 600, never commit).
- OSINT (Shodan/Censys) is constrained to **this hostname**, never internet-wide.
- GraphQL prove is `{__typename}` only (no schema dump).
- IDOR prove compares **your** two sessions; it does not pull other users' data.
- JWT prove decodes header/payload only (no secret cracking, no `alg=none` attack).

---

## Tier 1 -- authenticated surface & high-signal extras

| Feature | How |
|---------|-----|
| Auth session (cookie A + headers) | `python recon.py session set --cookie "..." --header "Authorization: Bearer ..."` |
| Multi-scope run | `python recon.py run --scope-all --modules subdomains,dns,httpprobe` |
| JS intel (maps, routes, lib versions) | module `jsintel` |
| API / OpenAPI / IDOR-shaped URLs | module `apis` |
| Extra takeover (package.json, CDN 404) | module `takeover_plus` |
| Tech-tagged nuclei pack | automatic inside `nuclei` when httpx tech matches |
| Safe 401/403 header/path probes | module `bypass403` (no password spray) |

```bash
python recon.py session set --cookie "sid=abc"
python recon.py example.com --modules httpprobe,crawl,js,jsintel,apis,bypass403
python recon.py playbook run auth-surface --target example.com
```

```bash
python recon.py session set --cookie "sid=abc" --header "Authorization: Bearer ..."
python recon.py run --target example.com --modules jsintel,apis,bypass403,takeover_plus
python recon.py run --scope-all --modules subdomains,dns,httpprobe
```

---

## Tier 2 -- more surface, still in-scope

| Feature | How |
|---------|-----|
| Capped DNS permutations | module `permute` (alterx/dnsgen; dnsx only if dns is not in the same run) |
| In-scope port probe | module `ports` (naabu connect-scan + httpx) |
| gf extras (redirect / lfi / interestingparams) | module `gfextra` |
| Well-known / robots / security.txt | module `wellknown` |
| Scoped Shodan/Censys | module `osint` (hostname query only) |
| GitHub/GitLab URLs + optional trufflehog | module `gitrecon` (one public repo) |
| WAF backoff | httpprobe writes `waf_detected.txt`; Cloudflare -> `python recon.py rate stealth` |

```bash
python recon.py playbook run hunter --target example.com
python recon.py playbook run ports-hint --target example.com
python recon.py example.com --modules permute,ports,wellknown,gfextra,osint,gitrecon
```

---

## Tier 3 -- safe prove extras (C1 -> C2)

Set `oast_base_url` in `config/exploit_policy.json` for redirect/SSRF canaries.

| Technique | Input | Action |
|-----------|--------|--------|
| `jwt_inspect` | JWT-shaped token in evidence | Decode header/payload only (`alg=none` stays needs_manual) |
| `cors_origin` | CORS candidate | Origin canary; confirm ACAO + credentials |
| `graphql_typename` | GraphQL URL | POST `{__typename}` only |
| `redirect_canary` | Redirect candidate | Bounce to OAST or `.invalid` |
| `idor_session_diff` | IDOR-shaped URL | GET with cookie A vs cookie B |

Matching recon modules: `redirect`, `cors`, `graphql` (detection), then `python recon.py prove`.

```bash
python recon.py session set --cookie "userA=..." --cookie-b "userB=..."
python recon.py findings reindex
python recon.py prove queue example.com
python recon.py prove run --target example.com --technique cors_origin
python recon.py prove run --target example.com --technique idor_session_diff
```

```bash
python recon.py prove run --target example.com --technique jwt_inspect
python recon.py prove run --target example.com --technique graphql_typename
python recon.py prove run --target example.com --technique redirect_canary
```

---

## Tier 4 -- hunt ops (HAR, resume, evidence, inbox)

| Feature | How |
|---------|-----|
| HAR import | `python recon.py har --target example.com --file capture.har` keeps in-scope URLs in `urls.txt` and can copy a Cookie into the session |
| Target wordlist | `python recon.py wordlist-target --target example.com` writes `wordlist_target.txt` |
| Resume a partial run | `python recon.py example.com --resume` skips a finished tool file. Exit 124 runs that tool again. `--force` redoes the work. |
| Evidence ZIP | `python recon.py evidence --target example.com` writes `evidence_<target>_....zip` |
| Notify | if `notify` CLI is installed, a C1+ vuln count is sent at end of a successful run |
| Hunter inbox | `python recon.py inbox --target example.com` |

```bash
python recon.py har --target example.com --file ~/Downloads/app.har
python recon.py example.com --resume --modules crawl,js,jsintel,apis
python recon.py findings reindex
python recon.py inbox --target example.com
python recon.py evidence --target example.com
python recon.py graph show --target example.com
```

```bash
python recon.py har --target example.com --file capture.har
python recon.py run --target example.com --resume
python recon.py wordlist-target --target example.com
python recon.py evidence --target example.com
```

---

## New modules (pipeline order)

```
subdomains -> permute -> dns -> httpprobe -> (tls, wellknown, ports, crawl)
         -> js -> jsintel -> params -> apis -> content -> bypass403 -> gfextra
         -> xss -> sqli -> ssrf_ssti -> redirect -> cors -> graphql
         -> nuclei -> cloud -> takeover_plus -> osint -> gitrecon -> screenshots
```

Passive name sources run together. Amass uses its own cap inside that pool.
One dnsx pass writes resolved hosts, records, and CNAME lines. httpx probes
before naabu. tls, well-known, ports, and crawl overlap after alive.txt and
join before js. xss, sqli, ssrf, and gfextra share one URL classification.

List descriptions anytime: `python recon.py modules`.

Playbooks: `auth-surface`, `hunter` (includes enum/crawl/js so extras have inputs),
`api-surface`, `js-deep`, `ports-hint`, `content-light`, `prove-prep`,
`vuln-pass`, `takeover-first`.

---

## Output files (hunter extras)

Under `~/.reconkit/output/<target>/`:

Per-source lists (subdomains, crawl) are written to `tools/<stage>/<tool>.txt`
as that tool finishes. The merge file is updated after each of those tools,
then finalized at stage end. A stage with one result writes that file once at
the output root and keeps the exit code under `tools/`.

Example while subfinder is done and amass is still running:

```
tools/subdomains/subfinder.txt
subdomains.txt          # already has subfinder names
```

Amass runs with the other passive sources and is capped at 180s (`python recon.py set RECON_AMASS_TIMEOUT 900`, max 900). dnsx, httpx,
tlsx, crawl, and each nuclei pack have their own caps (`RECON_DNSX_TIMEOUT`,
`RECON_HTTPX_TIMEOUT`, `RECON_TLSX_TIMEOUT`, `RECON_CRAWL_TIMEOUT`,
`RECON_NUCLEI_TIMEOUT`). A cap records exit 124 beside that tool file, and
`--resume` runs the tool again. When httpx hits the cap and `alive.txt` already
lists hosts, the previous host list stays. A missing httpx or crawler leaves
`alive.txt` and `urls.txt` in place. Ctrl+C stops a hung scan.

`--resume` skips a finished tool file. A missing `.rc` marker counts as finished.
An older run that has only the merged file and no `tools/<stage>/` files still
skips that stage. `run_meta.json` records the run.
`tech_routes.txt` lists prove techniques that match files already on disk.
`param_priority.txt` is a short parameter list. `tools/<stage>/dropped.txt`
records out-of-scope and wildcard drops (capped).

`reviews/<phase>.txt` is an opt-in model note (`--review` or `RECON_SUPERVISOR=1`).
The scan still chooses every module. The note says what landed, what to ignore,
and which existing prove technique is worth a look. `reviews/summary.txt`
is written at the end of a run that was not stopped. Read them as
`reviews/<phase>.txt` under the target output directory.

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
| `wordlist_target.txt` | `python recon.py wordlist-target` |
| `evidence_*.zip` | `python recon.py evidence` |

Session file: `~/.reconkit/session.json` (not under output/).
