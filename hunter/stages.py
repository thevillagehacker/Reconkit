"""Extra recon stages (hunter tiers). Lazy-imports reconkit to avoid cycles."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from hunter import session as sess

_API_PATH_RE = re.compile(
    r"""["'](/(?:api|graphql|rest|v[0-9]+)/[A-Za-z0-9_./\-]+)["']""",
)
_ROUTE_RE = re.compile(
    r"""["'](/[A-Za-z0-9_./\-]*(?:admin|internal|debug|manage|private|dashboard)[A-Za-z0-9_./\-]*)["']""",
)
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=\s*(\S+)")
_LIB_RE = re.compile(
    r"(jquery|react|angular|vue|next|webpack|bootstrap|lodash|moment)[^\n]{0,40}"
    r"(?:version|[vV])?[^\d]{0,8}(\d+\.\d+(?:\.\d+)?)",
    re.I,
)
_PKG_RE = re.compile(r'"(?:name|dependencies)"\s*:')
_GITHUB_RE = re.compile(r"https?://(?:www\.)?(?:github\.com|gitlab\.com)/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+")
_GIT_DIR_RE = re.compile(r"https?://[^\s\"']+/\.git(?:/config)?", re.I)

WELLKNOWN = [
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/.well-known/openid-configuration", "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association", "/apple-app-site-association",
    "/favicon.ico", "/humans.txt", "/crossdomain.xml",
]

BYPASS_HEADERS = [
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
]

TECH_TAGS = {
    "wordpress": "wordpress", "wp ": "wordpress", "php": "php",
    "jenkins": "jenkins", "gitlab": "gitlab", "grafana": "grafana",
    "kibana": "kibana", "nginx": "nginx", "apache": "apache",
    "iis": "iis", "tomcat": "tomcat", "django": "python",
    "flask": "python", "laravel": "php", "spring": "spring",
    "graphql": "graphql", "kubernetes": "kubernetes", "minio": "minio",
}

PORT_LIST = "80,443,8080,8443,3000,5000,8000,8888,9000,9090,9200,9443,10443,27017,6379"

WAF_HINTS = ("cloudflare", "akamai", "sucuri", "imperva", "incapsula", "mod_security", "aws-waf")


def _rk():
    import reconkit as rk
    return rk


def _headers_httpx() -> list[str]:
    return sess.httpx_h_flags()


def _write(rk, path: Path, lines) -> int:
    text = "\n".join(str(x).strip() for x in lines if str(x).strip())
    path.write_text(text + ("\n" if text else ""), encoding="utf-8")
    return len(text.splitlines()) if text else 0


def stage_permute(target: str, outdir: Path) -> None:
    """Capped DNS permutations of known subdomains (alterx/dnsgen) then dnsx."""
    rk = _rk()
    rk.step("DNS permutations (capped)", phase="permute")
    subs = outdir / "subdomains.txt"
    if not subs.exists():
        rk.warn("no subdomains.txt; skipping permute.")
        return
    names = [ln.strip() for ln in subs.read_text(errors="ignore").splitlines() if ln.strip()]
    cap = min(400, max(50, rk._host_cap(200)))
    seed = names[:80]
    generated: set[str] = set()
    alterx = rk.which("alterx")
    dnsgen = rk.which("dnsgen")
    if alterx and seed:
        r = rk.pipeline([["alterx", "-silent"]], input_data=("\n".join(seed) + "\n").encode())
        generated.update(
            h for h in (r.decode(errors="ignore").splitlines()) if rk.host_belongs_to_target(h, target)
        )
    elif dnsgen and seed:
        r = rk.pipeline([["dnsgen", "-"]], input_data=("\n".join(seed) + "\n").encode())
        generated.update(
            h for h in (r.decode(errors="ignore").splitlines()) if rk.host_belongs_to_target(h, target)
        )
    else:
        # tiny built-in prefixes
        apex = rk._normalize_host(target)
        for pfx in ("dev", "staging", "stage", "api", "admin", "vpn", "git", "ci", "jenkins", "vault"):
            generated.add(f"{pfx}.{apex}")
    generated = {g for g in generated if rk.is_valid_hostname(g)}
    if len(generated) > cap:
        generated = set(sorted(generated)[:cap])
    (outdir / "permute_raw.txt").write_text("\n".join(sorted(generated)) + "\n", encoding="utf-8")
    dnsx = rk.which("dnsx")
    resolved: list[str] = []
    if dnsx and generated:
        r = rk.pipeline([["dnsx", "-silent"]], input_data=("\n".join(generated) + "\n").encode())
        resolved = [ln.strip() for ln in r.decode(errors="ignore").splitlines() if ln.strip()]
    _write(rk, outdir / "permute_resolved.txt", resolved)
    if resolved:
        existing = set(names)
        merged = sorted(existing | set(resolved))
        subs.write_text("\n".join(merged) + "\n", encoding="utf-8")
        rk.ok(f"permute: {len(resolved)} resolved names merged into subdomains.txt")
    else:
        rk.warn("permute: no extra resolved names")


def stage_ports(target: str, outdir: Path) -> None:
    """TCP CONNECT scan of in-scope hosts (naabu, no root) then httpx on http ports."""
    rk = _rk()
    rk.step("In-scope port probe (naabu connect)", phase="ports")
    src = outdir / "resolved.txt"
    if not src.exists() or not src.stat().st_size:
        src = outdir / "subdomains.txt"
    hosts: list[str] = []
    if src.exists():
        hosts = [
            rk.strip_ansi(ln).strip().split()[0]
            for ln in src.read_text(encoding="utf-8", errors="ignore").splitlines()
            if ln.strip()
        ]
        hosts = [h for h in hosts if h and rk.host_belongs_to_target(h, target)]
    if not hosts:
        apex = rk._normalize_host(target)
        hosts = [apex]
        rk.warn(
            f"no resolved.txt/subdomains.txt — scanning apex only ({apex}). "
            "Run subdomains,dns first for more hosts."
        )
    cap = rk._host_cap(40)
    hosts = hosts[:cap]
    naabu = rk.which("naabu")
    if not naabu:
        rk.warn("naabu not found; skipping ports (install via setup).")
        return

    tdir = rk.tool_dir(outdir, "ports")
    hostfile = tdir / "hosts.txt"
    raw_out = tdir / "naabu.txt"
    rk.write_host_list(hostfile, hosts)
    rk.info(f"naabu CONNECT scan · {len(hosts)} host(s) · ports {PORT_LIST}")

    # Default naabu scan-type is SYN (needs root) and stdin can sit until -irt (3m).
    # Use -list + CONNECT + skip host-discovery. Hard-kill after 180s.
    attempts = [
        [naabu, "-list", str(hostfile), "-p", PORT_LIST,
         "-scan-type", "c", "-skip-host-discovery",
         "-silent", "-rate", "150", "-timeout", "1000", "-retries", "1",
         "-o", str(raw_out)],
        [naabu, "-list", str(hostfile), "-p", PORT_LIST,
         "-s", "c", "-silent", "-rate", "150", "-timeout", "1000",
         "-o", str(raw_out)],
        [naabu, "-list", str(hostfile), "-p", PORT_LIST,
         "-scan-type", "c", "-silent", "-timeout", "1000", "-o", str(raw_out)],
    ]
    last = None
    for cmd in attempts:
        last = rk.run(cmd, capture=True, timeout=180)
        err = (last.stderr or b"").decode(errors="ignore").lower()
        if last.returncode == 124:
            rk.warn("naabu hit 180s cap — using whatever it already wrote to tools/ports/naabu.txt")
            break
        if last.returncode == 0:
            break
        if "unknown" in err or "flag" in err or "invalid" in err:
            continue
        break

    blob = ""
    if raw_out.exists():
        blob = raw_out.read_text(encoding="utf-8", errors="ignore")
    if not blob and last is not None:
        blob = (last.stdout or b"").decode(errors="ignore")
        rk.save_tool_raw(outdir, "ports", "naabu", blob)
    lines = [
        ln.strip() for ln in rk.strip_ansi(blob).splitlines()
        if ln.strip() and ":" in ln and not ln.strip().startswith("{")
    ]
    kept = []
    for ln in lines:
        host = ln.split(":")[0]
        if rk.host_belongs_to_target(host, target):
            kept.append(ln)
    _write(rk, outdir / "ports.txt", kept)
    rk.ok(f"naabu: {len(kept)} open port(s) → tools/ports/naabu.txt · ports.txt")

    http_ports = [
        ln for ln in kept
        if ln.rsplit(":", 1)[-1] in {
            "80", "443", "8080", "8443", "3000", "5000", "8000", "8888", "9000", "9443",
        }
    ]
    if http_ports and rk.which("httpx"):
        urls = []
        for hp in http_ports:
            host, port = hp.rsplit(":", 1)
            scheme = "https" if port in {"443", "8443", "9443"} else "http"
            urls.append(f"{scheme}://{host}:{port}")
        extra = rk.pipeline(
            [["httpx", "-silent", "-sc", "-title", *_headers_httpx()]],
            input_data=("\n".join(urls) + "\n").encode(),
        )
        if not extra.strip():
            extra = rk.pipeline(
                [["httpx", "-silent", "-status-code", "-title", *_headers_httpx()]],
                input_data=("\n".join(urls) + "\n").encode(),
            )
        text = rk.strip_ansi(extra.decode("utf-8", errors="replace"))
        rk.write_utf8(outdir / "ports_http.txt", text + ("" if not text or text.endswith("\n") else "\n"))
        rk.save_tool_raw(outdir, "ports", "httpx", text)
        rk.ok(f"ports: {len(kept)} open, {len(http_ports)} http-ish → ports_http.txt")
    else:
        rk.ok(f"ports: {len(kept)} open services → ports.txt")


def stage_wellknown(target: str, outdir: Path, alive_file: Path) -> None:
    rk = _rk()
    rk.step("Well-known / robots / sitemap / security.txt", phase="wellknown")
    if not rk.which("httpx"):
        rk.warn("httpx missing; skipping wellknown.")
        return
    hosts = rk._first_tokens(alive_file)[: rk._host_cap(15)] if alive_file.exists() else []
    if not hosts:
        rk.warn(
            "alive.txt empty — seeding wellknown with the target host. "
            "Run httpprobe first for full coverage."
        )
        hosts = [target]
    hits: list[str] = []
    for host in hosts:
        rk._rate_delay()
        r = rk.pipeline(
            [["httpx", "-silent", "-mc", "200,204,301,302,401,403",
              "-path", ",".join(WELLKNOWN), *_headers_httpx()]],
            input_data=(host + "\n").encode(),
        )
        hits.extend(ln for ln in r.decode(errors="ignore").splitlines() if ln.strip())
    n = _write(rk, outdir / "wellknown.txt", hits)
    rk.ok(f"well-known hits: {n} → wellknown.txt")


def stage_jsintel(target: str, outdir: Path, js_file: Path) -> None:
    """Sourcemaps, hidden routes, API paths, lib versions from fetched JS."""
    rk = _rk()
    rk.step("JS intel (maps, routes, APIs, lib versions)", phase="jsintel")
    js_urls = []
    if js_file.exists():
        js_urls = [ln.strip() for ln in js_file.read_text(errors="ignore").splitlines() if ln.strip()]
    js_urls = [u for u in js_urls if rk.url_belongs_to_target(u, target)]
    subjs = rk.which("subjs")
    if subjs and (outdir / "urls.txt").exists():
        r = rk.pipeline([["subjs"]], input_data=(outdir / "urls.txt").read_bytes())
        extra = rk.filter_urls_to_target(r.decode(errors="ignore").splitlines(), target)
        if extra:
            js_urls = sorted(set(js_urls) | set(extra))
            js_file.write_text("\n".join(js_urls) + "\n", encoding="utf-8")
    js_urls = js_urls[: int(rk.rate_settings().get("js_cap") or 80)]
    curl = rk.which("curl")
    if not curl or not js_urls:
        rk.warn("no JS URLs or curl; skipping jsintel.")
        return
    routes: set[str] = set()
    apis: set[str] = set()
    maps: set[str] = set()
    libs: set[str] = set()
    github: set[str] = set()
    for u in js_urls:
        rk._rate_delay()
        r = rk.run([curl, "-s", "-k", "--max-time", "12", *sess.curl_flags(), u], capture=True)
        body = (r.stdout or b"").decode(errors="ignore")
        for m in _ROUTE_RE.finditer(body):
            routes.add(m.group(1))
        for m in _API_PATH_RE.finditer(body):
            apis.add(m.group(1))
        for m in _SOURCEMAP_RE.finditer(body):
            maps.add(urljoin(u, m.group(1)))
        for m in _LIB_RE.finditer(body):
            libs.add(f"{m.group(1).lower()}@{m.group(2)}")
        for m in _GITHUB_RE.finditer(body):
            github.add(m.group(0).rstrip(").,"))
    payload = {
        "routes": sorted(routes)[:500],
        "api_paths": sorted(apis)[:500],
        "sourcemaps": sorted(maps)[:200],
        "libraries": sorted(libs)[:200],
        "github": sorted(github)[:100],
    }
    (outdir / "js_intel.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _write(rk, outdir / "api_paths.txt", payload["api_paths"])
    rk.ok(
        f"jsintel: {len(routes)} routes, {len(apis)} api paths, "
        f"{len(maps)} sourcemaps, {len(libs)} lib versions"
    )


def stage_apis(target: str, outdir: Path, urls_file: Path) -> None:
    rk = _rk()
    rk.step("API surface (OpenAPI / graphql / /api/ paths)", phase="apis")
    urls = []
    if urls_file.exists():
        urls = [ln.strip() for ln in urls_file.read_text(errors="ignore").splitlines() if ln.strip()]
    api_urls = [
        u for u in urls
        if rk.url_belongs_to_target(u, target)
        and re.search(r"/api|/graphql|/swagger|/openapi|/v[0-9]+/", u, re.I)
    ]
    extra = []
    p = outdir / "api_paths.txt"
    if p.exists():
        extra = [ln.strip() for ln in p.read_text(errors="ignore").splitlines() if ln.strip()]
    bases: list[str] = []
    alive = outdir / "alive_urls.txt"
    if alive.exists():
        bases = [
            b.rstrip("/") for b in rk._first_tokens(alive)[:15]
            if str(b).startswith("http")
        ]
    for path in extra:
        if not path.startswith("/"):
            path = "/" + path
        for b in bases:
            u = b + path
            if rk.url_belongs_to_target(u, target):
                api_urls.append(u)
    api_urls = sorted(set(api_urls))[:2000]
    _write(rk, outdir / "api_urls.txt", api_urls)
    # IDOR-shaped params
    idor = [u for u in api_urls if re.search(r"(id=|user_id=|account_id=|uid=|org_id=)", u, re.I)]
    _write(rk, outdir / "idor_candidates.txt", idor[:500])
    rk.ok(f"apis: {len(api_urls)} API URLs, {len(idor)} IDOR-shaped, {len(extra)} from JS")


def stage_bypass403(target: str, outdir: Path, alive_file: Path) -> None:
    """Header/path 401/403 probes — no password spray."""
    rk = _rk()
    rk.step("401/403 header bypass probes", phase="bypass403")
    if not rk.which("httpx") or not alive_file.exists():
        rk.warn("httpx/alive missing; skipping bypass403.")
        return
    candidates = []
    for ln in alive_file.read_text(errors="ignore").splitlines():
        if "[401]" in ln or "[403]" in ln:
            tok = ln.split()[0]
            if tok.startswith("http"):
                candidates.append(tok)
    sens = outdir / "sensitive_paths_found.txt"
    if sens.exists():
        for ln in sens.read_text(errors="ignore").splitlines():
            if "[401]" in ln or "[403]" in ln:
                tok = ln.split()[0]
                if tok.startswith("http"):
                    candidates.append(tok)
    candidates = [u for u in candidates if rk.url_belongs_to_target(u, target)][:30]
    hits: list[str] = []
    from prove.http_util import http_get
    for url in candidates:
        base = http_get(url, timeout=8)
        if base.get("status") not in (401, 403):
            continue
        found = False
        for hk, hv in BYPASS_HEADERS:
            r = http_get(url, timeout=6, extra_headers={hk: hv})
            st = r.get("status")
            if st and st not in (401, 403, None) and st != base.get("status"):
                hits.append(f"{url}  header {hk}  {base.get('status')}→{st}")
                found = True
                break
        if found:
            continue
        parsed = urlparse(url)
        variants = [
            url.rstrip("/") + "/",
            url + "%2e",
            url.replace("://", "://./"),
        ]
        if parsed.path:
            variants.append(url + "/.")
        for v in variants:
            r = http_get(v, timeout=6)
            st = r.get("status")
            if st and st not in (401, 403, None) and st != base.get("status"):
                hits.append(f"{v}  {base.get('status')}→{st}")
                break
    n = _write(rk, outdir / "bypass403.txt", hits)
    rk.ok(f"bypass403: {n} status-changing path/header variants (manual review)")


def stage_gfextra(target: str, outdir: Path, urls_file: Path) -> None:
    rk = _rk()
    rk.step("gf extra patterns (redirect, lfi, interestingparams)", phase="gfextra")
    if not urls_file.exists() or not rk.which("gf"):
        rk.warn("gf/urls missing; skipping gfextra.")
        return
    data = urls_file.read_bytes()
    for pat, fname in (("redirect", "redirect_candidates.txt"),
                       ("lfi", "lfi_candidates.txt"),
                       ("interestingparams", "interesting_params.txt")):
        out = rk.pipeline([["gf", pat]], input_data=data)
        lines = rk.filter_urls_to_target(out.decode(errors="ignore").splitlines(), target)
        _write(rk, outdir / fname, lines[:3000])
    rk.ok("gf extra: redirect / lfi / interestingparams lists written")


def stage_redirect(target: str, outdir: Path) -> None:
    """Open-redirect canary: bounce to hunter-owned or .invalid host."""
    rk = _rk()
    rk.step("Open-redirect canaries", phase="redirect")
    src = outdir / "redirect_candidates.txt"
    if not src.exists() or not src.stat().st_size:
        src = outdir / "urls.txt"
    if not src.exists() or not rk.which("qsreplace") or not rk.which("httpx"):
        rk.warn("no redirect candidates or tools; skipping.")
        return
    bounce = "https://rk-redirect-check.invalid/"
    try:
        from prove.policy import load_policy
        oast = (load_policy().get("oast_base_url") or "").strip().rstrip("/")
        if oast.startswith("http"):
            bounce = oast + "/rk-redirect"
    except Exception:
        pass
    data = "\n".join(rk.filter_urls_to_target(src.read_text(errors="ignore").splitlines(), target)[:200])
    r = rk.pipeline(
        [["qsreplace", bounce], ["httpx", "-silent", "-location", *_headers_httpx()]],
        input_data=(data + "\n").encode(),
    )
    hits = [ln for ln in r.decode(errors="ignore").splitlines()
            if "rk-redirect" in ln.lower() or "rk-redirect-check.invalid" in ln.lower()]
    n = _write(rk, outdir / "redirect_hits.txt", hits)
    rk.ok(f"redirect: {n} Location/body hits for canary bounce")


def stage_cors(target: str, outdir: Path, alive_file: Path) -> None:
    rk = _rk()
    rk.step("CORS reflection check (Origin canary)", phase="cors")
    hosts = rk._first_tokens(alive_file)[: rk._host_cap(20)] if alive_file.exists() else []
    origin = "https://rk-cors-check.invalid"
    hits = []
    from prove.http_util import http_get
    for host in hosts:
        url = host if host.startswith("http") else f"https://{host}/"
        if not rk.url_belongs_to_target(url, target):
            continue
        r = http_get(url, timeout=8, extra_headers={"Origin": origin}, merge_session=True)
        hdrs = r.get("headers") or {}
        acao = hdrs.get("Access-Control-Allow-Origin") or hdrs.get("access-control-allow-origin") or ""
        acac = hdrs.get("Access-Control-Allow-Credentials") or hdrs.get("access-control-allow-credentials") or ""
        if origin in acao or acao.strip() == "*":
            hits.append(f"{url}  ACAO={acao}  ACAC={acac}")
    n = _write(rk, outdir / "cors_candidates.txt", hits)
    rk.ok(f"cors: {n} reflected/* ACAO (confirm credentials + impact)")


def stage_graphql(target: str, outdir: Path, urls_file: Path) -> None:
    """Detect GraphQL endpoints; optional introspection (schema map, not a report)."""
    rk = _rk()
    rk.step("GraphQL endpoint detect", phase="graphql")
    urls = []
    if urls_file.exists():
        urls = [ln.strip() for ln in urls_file.read_text(errors="ignore").splitlines() if ln.strip()]
    gq = [u for u in urls if rk.url_belongs_to_target(u, target) and "graphql" in u.lower()]
    # well-known
    alive = outdir / "alive_urls.txt"
    if alive.exists():
        for base in rk._first_tokens(alive)[:10]:
            if not base.startswith("http"):
                continue
            gq.append(base.rstrip("/") + "/graphql")
    gq = sorted(set(gq))[:40]
    hits = []
    q = '{"query":"{__typename}"}'
    import urllib.error
    import urllib.request
    import ssl
    for url in gq:
        try:
            req = urllib.request.Request(
                url,
                data=q.encode(),
                headers={"Content-Type": "application/json", "User-Agent": "reconkit-gql/3.0",
                         **sess.headers()},
                method="POST",
            )
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                body = resp.read(2000).decode("utf-8", errors="replace")
                if "__typename" in body or '"data"' in body or '"errors"' in body:
                    hits.append(f"{url}  HTTP {getattr(resp, 'status', resp.getcode())}  {body[:120].replace(chr(10), ' ')}")
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(2000).decode("utf-8", errors="replace")
            except Exception:
                pass
            if "__typename" in body or '"errors"' in body or "graphql" in body.lower():
                hits.append(f"{url}  HTTP {e.code}  {body[:120].replace(chr(10), ' ')}")
        except Exception:
            continue
    n = _write(rk, outdir / "graphql_endpoints.txt", hits)
    rk.ok(f"graphql: {n} responding endpoints (introspection not enabled by default)")


def stage_takeover_plus(target: str, outdir: Path, urls_file: Path) -> None:
    """package.json / dangling JS CDN / NS hints — no auto-claim."""
    rk = _rk()
    rk.step("Extra takeover surface (npm, CDN 404, git)", phase="takeover_plus")
    findings: list[str] = []
    curl = rk.which("curl")
    urls = []
    if urls_file.exists():
        urls = rk.filter_urls_to_target(urls_file.read_text(errors="ignore").splitlines(), target)
    pkg = [u for u in urls if u.rstrip("/").endswith("package.json")][:15]
    for u in pkg:
        if not curl:
            break
        r = rk.run([curl, "-s", "-k", "-o", "-", "-w", "%{http_code}", "--max-time", "10", u], capture=True)
        body = (r.stdout or b"").decode(errors="ignore")
        if '"name"' in body and "dependencies" in body:
            findings.append(f"package.json {u}")
    cdn_404 = [u for u in urls if re.search(r"unpkg\.com|cdnjs\.cloudflare|jsdelivr\.net", u, re.I)][:20]
    for u in cdn_404:
        if not curl:
            break
        r = rk.run([curl, "-s", "-k", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8", u], capture=True)
        code = (r.stdout or b"").decode(errors="ignore").strip()
        if code == "404":
            findings.append(f"dangling-cdn 404 {u}")
    n = _write(rk, outdir / "takeover_plus.txt", findings)
    rk.ok(f"takeover_plus: {n} extra candidates")


def stage_osint(target: str, outdir: Path) -> None:
    """Shodan/Censys for this hostname/IPs only — never internet-wide."""
    rk = _rk()
    rk.step("Scoped OSINT (Shodan/Censys on this target only)", phase="osint")
    rows: list[str] = []
    shodan = rk.which("shodan")
    if shodan and (os_env("SHODAN_API_KEY")):
        q = f'ssl.cert.subject.CN:"{target}"'
        r = rk.run([shodan, "search", "--limit", "20", q], capture=True)
        for ln in (r.stdout or b"").decode(errors="ignore").splitlines():
            host = rk._normalize_host(ln.split()[0] if ln.strip() else "")
            if host and (rk.host_belongs_to_target(host, target) or re.match(r"\d+\.\d+\.\d+\.\d+", host)):
                rows.append("shodan " + ln.strip()[:300])
    else:
        rk.warn("shodan CLI/key missing; skipping Shodan (in-scope only).")
    censys = rk.which("censys")
    if censys and os_env("CENSYS_API_ID"):
        try:
            r = rk.run(
                [censys, "search", f"names:{target}", "--pages", "1"],
                capture=True,
            )
            for ln in (r.stdout or b"").decode(errors="ignore").splitlines():
                if ln.strip():
                    rows.append("censys " + ln.strip()[:300])
        except Exception:
            rk.warn("censys search failed; skipping.")
    n = _write(rk, outdir / "osint.txt", rows)
    rk.ok(f"osint: {n} in-scope lines")


def os_env(name: str) -> str:
    import os
    return os.environ.get(name) or ""


def stage_gitrecon(target: str, outdir: Path) -> None:
    rk = _rk()
    rk.step("Git/GitHub URL harvest + optional trufflehog", phase="gitrecon")
    blob = ""
    for name in ("urls.txt", "js_intel.json", "js_secrets_and_endpoints.json", "sensitive_paths_found.txt"):
        p = outdir / name
        if p.exists():
            blob += p.read_text(errors="ignore") + "\n"
    git_urls = sorted(set(_GITHUB_RE.findall(blob) + _GIT_DIR_RE.findall(blob)))
    git_urls = [u for u in git_urls if "github.com" in u or "gitlab.com" in u or "/.git" in u][:40]
    _write(rk, outdir / "git_urls.txt", git_urls)
    hog = rk.which("trufflehog")
    if hog and git_urls:
        # public git URLs only; no clone bomb
        r = rk.run(
            [hog, "git", git_urls[0], "--no-update", "--json"],
            capture=True,
        )
        (outdir / "trufflehog.jsonl").write_bytes(r.stdout or b"")
        rk.ok(f"gitrecon: {len(git_urls)} URLs, trufflehog on {git_urls[0]}")
    else:
        rk.ok(f"gitrecon: {len(git_urls)} git URLs (trufflehog skipped)")


def detect_waf(alive_file: Path) -> list[str]:
    hits = []
    if not alive_file.exists():
        return hits
    for ln in alive_file.read_text(errors="ignore").splitlines():
        low = ln.lower()
        for w in WAF_HINTS:
            if w in low:
                hits.append(w)
    return sorted(set(hits))


def nuclei_tech_tags(alive_file: Path) -> list[str]:
    tags: set[str] = set()
    if not alive_file.exists():
        return []
    text = alive_file.read_text(errors="ignore").lower()
    for needle, tag in TECH_TAGS.items():
        if needle in text:
            tags.add(tag)
    return sorted(tags)
