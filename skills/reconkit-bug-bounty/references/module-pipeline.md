# Module pipeline (reconkit)

## Bootstrap

1. **subdomains** — required first for multi-host targets.
2. If target is a single IP/host already known, still run subdomains once (may just yield root).

## Unblockers

| After | Run next |
|-------|----------|
| subdomains | `dns` + `httpprobe` together when both runnable |
| httpprobe | `tls`, `crawl`, `content`, `nuclei`, `screenshots` |
| crawl → urls.txt | `js`, `params`, `xss`, `sqli`, `ssrf_ssti`, `cloud` |

## Yield-based decisions

- **subdomains.txt lines high, alive.txt empty** → fix connectivity / re-run httpprobe; do not start vuln URL modules.
- **alive.txt high, urls.txt empty** → crawl before xss/sqli.
- **urls high** → prefer `js` + `nuclei` before heavy `content` fuzz on entire scope.
- **nuclei critical/high present** → note for analyst; optional later prove `nuclei_recheck`.
- **cname_takeover_candidates non-empty** → elevate priority in report; human validates.

## Time budget (max_steps)

Assume `max_steps` ~ 8–12:

| Steps | Goal |
|------:|------|
| 1 | subdomains |
| 2 | dns + httpprobe |
| 3 | crawl (or tls) |
| 4 | js + params |
| 5–6 | nuclei + one of xss/sqli/ssrf/cloud |
| 7 | remaining vuln / content |
| 8 | screenshots optional / done |

Skip optional stages early if high-signal findings already exist and remaining modules are low ROI.
