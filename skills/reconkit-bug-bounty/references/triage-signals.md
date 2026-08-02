# Triage signals from reconkit artifacts

## High priority (call out in summaries)

| Artifact / signal | Why |
|-------------------|-----|
| `cname_takeover_candidates.txt` | Subdomain takeover $ / impact |
| `js_secrets_and_endpoints.json` high-sev keys | Creds, cloud keys, webhooks |
| nuclei critical/high | CVE / exposed panels |
| open S3 / cloud listable | Data exposure |
| admin / login / grafana / jenkins titles in alive | Privileged surface |
| large param surface | IDOR/injection research later |

## Medium

- Interesting tech stack (Next.js, GraphQL, Spring, WordPress)
- Sensitive paths from content module
- TLS issues (expired, mismatch) — often low bounty alone

## Noise (do not over-index)

- Generic marketing subdomains with no alive service
- Info-severity nuclei templates without context
- Huge URL lists without params or auth surface

## Summary style

```
- subdomains: N lines; sample: a,b,c
- alive: M hosts; tech highlights: ...
- urls: K; js secrets categories: ...
- nuclei: count by severity if known
- NEXT: modules [..] because [signal]
```
