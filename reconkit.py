#!/usr/bin/env python3
"""
reconkit.py — Cross-platform setup & orchestrator for authorized bug bounty recon
===================================================================================

Version: 3.0.0

Works on Windows, Linux, and macOS.

COMMANDS
--------
  checkenv            Check OS, permissions, and prerequisites (Go, Python, Git, Rust)
  setup               Install Go/Rust/Python tools, gf patterns, env vars, config
  wordlists           Download SecLists, OneListForAll, resolvers
  verify              Confirm which tools are actually on PATH
  scope add/list/check  Manage your authorized-target scope file (the safety gate)
  keys set/list/remove   Manage optional API keys (stored outside this script's source)
  run --target <t> --modules <...>   Run the recon pipeline against an in-scope target
  modules             List available recon modules
  prove …             Safe validation (queue/run) — also: python recon_prove.py

INTERACTIVE SHELL
-----------------
  python3 recon_shell.py          # cyber-themed prompt (preferred in v3.0.0)
  python3 reconkit.py shell       # same shell, launched from reconkit
  python3 recon_prove.py run --target <domain>

VERBOSITY
---------
  --verbose N / -v N   (0=quiet, 1=normal, 2=debug, 3=live tool output)
  --debug              shortcut for --verbose 2

AUTHORIZATION GATE
------------------
Nothing in `run` executes against a target that is not explicitly listed
in ~/.reconkit/scope.txt. Add targets with `scope add`, which requires you to type
'yes' to confirm you hold written authorization (bug bounty scope, signed pentest
engagement, or your own infrastructure).

WHAT THIS DOES NOT AUTOMATE (BY DESIGN)
----------------------------------------
  - Internet-wide Shodan/Censys dorking for vulnerable devices unrelated to your
    scoped target (e.g. "find every exposed Cisco vManage / FortiOS / n8n server
    on the internet"). That is mass scanning of third-party infrastructure with
    no relationship to an authorized engagement — not bug bounty recon.
  - Live remote-code-execution payloads (e.g. SSTI payloads that actually spawn
    a shell, as opposed to a `{{7*7}}`-style detection canary).
  - Sending your target's URLs/data to third-party SaaS callback or "blind XSS"
    services (e.g. Knoxss, xss.report) — that shares scope data with a third
    party without your explicit say-so per call.
  - Active exploitation tools (sqlmap, ghauri). This toolkit only surfaces
    *candidate* vulnerable attack vectors (via gf patterns, detection canaries,
    and dalfox's reflected/DOM XSS checks). The optional *prove* layer
    (v3.0.0) re-checks candidates with non-destructive canaries only — it does
    not dump databases, spawn shells, or run exploit frameworks.
  These are excluded regardless of target, not just for out-of-scope targets.

USAGE EXAMPLES
--------------
    python3 reconkit.py setup
    python3 reconkit.py scope add example.com
    python3 reconkit.py run --target example.com
    python3 reconkit.py run --target example.com --modules subdomains,dns,httpprobe,nuclei
    python3 reconkit.py -v 3 run --target example.com --modules subdomains
    python3 reconkit.py prove queue --target example.com
    python3 recon_prove.py run --target example.com --dry-run
    python3 recon_shell.py
"""

__version__ = "3.0.0"

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import time
from pathlib import Path
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Paths / constants (cross-platform via pathlib)
# --------------------------------------------------------------------------- #

HOME = Path.home()
BASE_DIR = HOME / ".reconkit"
CONFIG_FILE = BASE_DIR / "config.json"
SCOPE_FILE = BASE_DIR / "scope.txt"
SECRETS_FILE = BASE_DIR / "secrets.env"
WORDLIST_DIR = BASE_DIR / "wordlists"
OUTPUT_DIR = BASE_DIR / "output"
GF_PATTERNS_DIR = HOME / ".gf"
NUCLEI_TEMPLATES_DIR = HOME / "nuclei-templates"

IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

GOPATH_DIR = HOME / "go"
GO_BIN_DIR = GOPATH_DIR / "bin"
CARGO_BIN_DIR = HOME / ".cargo" / "bin"


def _user_scripts_dir() -> Path:
    """Directory where `pip install --user` places console-script entry points.

    Tools are installed once into the user site (not a project venv) so they
    persist like Go/Cargo binaries under ~/go/bin and ~/.cargo/bin.
    """
    if hasattr(sysconfig, "get_preferred_scheme"):
        try:
            scheme = sysconfig.get_preferred_scheme("user")
            scripts = sysconfig.get_path("scripts", scheme)
            if scripts:
                return Path(scripts)
        except Exception:
            pass
    for scheme in ("nt_user", "posix_user", "osx_framework_user"):
        try:
            scripts = sysconfig.get_path("scripts", scheme)
            if scripts:
                return Path(scripts)
        except Exception:
            continue
    if IS_WINDOWS:
        ver = f"Python{sys.version_info.major}{sys.version_info.minor}"
        appdata = os.environ.get("APPDATA", str(HOME / "AppData" / "Roaming"))
        return Path(appdata) / "Python" / ver / "Scripts"
    return HOME / ".local" / "bin"


USER_SCRIPTS_DIR = _user_scripts_dir()
EXTRA_PATH_DIRS = [GO_BIN_DIR, CARGO_BIN_DIR, USER_SCRIPTS_DIR]

# --- Tool inventories, matching every tool named in the recon notes -------- #

# module path -> binary name
GO_TOOLS = {
    # ProjectDiscovery suite
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest": "subfinder",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest": "httpx",
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest": "nuclei",
    "github.com/projectdiscovery/katana/cmd/katana@latest": "katana",
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest": "dnsx",
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest": "naabu",
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest": "shuffledns",
    "github.com/projectdiscovery/chaos-client/cmd/chaos@latest": "chaos",
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest": "tlsx",
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest": "mapcidr",
    "github.com/projectdiscovery/notify/cmd/notify@latest": "notify",
    # tomnomnom's toolbox
    "github.com/tomnomnom/waybackurls@latest": "waybackurls",
    "github.com/tomnomnom/anew@latest": "anew",
    "github.com/tomnomnom/qsreplace@latest": "qsreplace",
    "github.com/tomnomnom/unfurl@latest": "unfurl",
    "github.com/tomnomnom/gf@latest": "gf",
    "github.com/tomnomnom/assetfinder@latest": "assetfinder",
    "github.com/tomnomnom/httprobe@latest": "httprobe",
    # Crawling & fuzzing
    "github.com/ffuf/ffuf/v2@latest": "ffuf",
    "github.com/jaeles-project/gospider@latest": "gospider",
    "github.com/hakluke/hakrawler@latest": "hakrawler",
    "github.com/hakluke/hakrevdns@latest": "hakrevdns",
    "github.com/edoardottt/cariddi/cmd/cariddi@latest": "cariddi",
    # XSS / vuln
    "github.com/hahwul/dalfox/v2@latest": "dalfox",
    "github.com/Emoe/kxss@latest": "kxss",
    "github.com/ferreiraklet/airixss@latest": "airixss",
    # URL / JS
    "github.com/lc/gau/v2/cmd/gau@latest": "gau",
    "github.com/lc/subjs@latest": "subjs",
    # Screenshots & misc
    "github.com/sensepost/gowitness@latest": "gowitness",
    "github.com/d3mondev/puredns/v2@latest": "puredns",
    "github.com/j3ssie/metabigor@latest": "metabigor",
    "github.com/gwen001/github-subdomains@latest": "github-subdomains",
    "github.com/trufflesecurity/trufflehog/v3@latest": "trufflehog",
}

# crates.io package -> binary name (installed via `cargo install`)
CARGO_TOOLS = {
    "feroxbuster": "feroxbuster",
    "findomain": "findomain",
    "x8": "x8",
}

# pip packages installed once into the user site-packages (pip install --user)
PIP_TOOLS = [
    "arjun",
    "uro",
    "shodan",
    "censys",
    "certstream",
    "dnsgen",
    "waymore",
    "bbrf",
]

# gf pattern repo (adds xss/sqli/ssrf/ssti/lfi/redirect/rce patterns for `gf`)
GF_PATTERNS_REPO = "https://github.com/1ndianl33t/Gf-Patterns.git"

# Known optional API keys and what they unlock. Values here are DESCRIPTIONS
# only, never actual secrets — real key values only ever live in
# ~/.reconkit/secrets.env (see `keys` command) or your shell environment,
# never hardcoded in this file.
KNOWN_API_KEYS = {
    "PDCP_API_KEY": "chaos (get a free key at https://cloud.projectdiscovery.io)",
    "GITHUB_TOKEN": "github-subdomains, and raises subfinder's GitHub-source rate limit",
    "SHODAN_API_KEY": "the shodan pip tool / subfinder's shodan source",
    "CENSYS_API_ID": "the censys pip tool / subfinder's censys source (also needs CENSYS_API_SECRET)",
    "SECURITYTRAILS_API_KEY": "subfinder's securitytrails source",
    "VIRUSTOTAL_API_KEY": "subfinder's virustotal source",
}

WORDLIST_TARGETS = {
    "seclists": "https://github.com/danielmiessler/SecLists.git",
    "onelistforall": "https://github.com/six2dez/OneListForAll.git",
}
RESOLVER_URLS = [
    "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
]

# Common sensitive/content-discovery paths (used when no wordlist file is given)
SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/config.php", "/wp-config.php.bak", "/.htaccess",
    "/server-status", "/.svn/entries", "/.bzr/README", "/CVS/Root",
    "/config.json", "/config.yaml", "/config.yml", "/settings.json", "/app.config",
    "/database.sql", "/db.sql", "/backup.sql", "/dump.sql",
    "/swagger.json", "/openapi.json", "/api-docs", "/swagger-ui.html",
    "/.aws/credentials", "/.docker/config.json", "/kubeconfig",
    "/graphql", "/graphiql", "/playground",
]

CNAME_TAKEOVER_FINGERPRINTS = [
    "s3", "cloudfront", "herokuapp", "github", "azure", "shopify",
    "fastly", "pantheon", "zendesk", "readme", "ghost", "surge", "bitbucket",
    "wordpress", "tumblr",
]

# Secret-extraction regexes applied to fetched JS (read-only pattern matching,
# not exploitation of anything found)
# Extracts bare URLs from output that isn't clean one-per-line — e.g. gospider
# prefixes most lines with tags like "[url] - [code-200] - https://...".
_URL_RE = re.compile(r"https?://[^\s'\"<>]+")


def _extract_urls(text: str) -> set[str]:
    return set(_URL_RE.findall(text))


JS_SECRET_PATTERNS = {
    "aws_keys": r"(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
    "google_api_keys": r"AIza[0-9A-Za-z_\-]{35}",
    "firebase_urls": r"[a-zA-Z0-9-]+\.firebaseio\.com|[a-zA-Z0-9-]+\.firebaseapp\.com",
    "s3_buckets": r"[a-zA-Z0-9.\-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9.\-]+",
    "azure_blobs": r"[a-zA-Z0-9-]+\.blob\.core\.windows\.net",
    "gcp_buckets": r"storage\.googleapis\.com/[a-zA-Z0-9\-]+",
    "slack_webhooks": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "discord_webhooks": r"https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+",
    "github_tokens": r"(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})",
    "jwt_tokens": r"eyJ[A-Za-z0-9_\-]*\.eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*",
    "private_keys": r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----",
    "internal_ips": r"(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})",
    "emails": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "graphql_endpoints": r"/[a-zA-Z0-9/_\-]*graphql[a-zA-Z0-9/_\-]*",
    "hidden_routes": r"[\"'][/][a-zA-Z0-9_/\-]*(admin|dashboard|manage|config|settings|internal|private|debug|api/v[0-9])[a-zA-Z0-9_/\-]*[\"']",
    "generic_secrets": r"(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth)[\"']?\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']",
}


# --------------------------------------------------------------------------- #
# Color support (cross-platform, auto-disabled when not useful)
# --------------------------------------------------------------------------- #

# colorama translates ANSI codes into native Win32 console calls, which works
# on old Windows (7/8, early Win10 builds) where the raw ENABLE_VIRTUAL_TERMINAL
# _PROCESSING trick below doesn't exist yet. It's optional — if it's not
# installed we fall back to the ctypes VT100-enabling approach, which still
# covers Windows 10 1511+ and every Linux/macOS terminal.
try:
    import colorama
    colorama.init()
    _COLORAMA_AVAILABLE = True
except ImportError:
    _COLORAMA_AVAILABLE = False


class Colors:
    """ANSI color codes. Auto-disabled if the terminal doesn't support them,
    output is redirected to a file/pipe, or NO_COLOR is set — so piping this
    script's output never ends up full of escape-code garbage."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BOLD_RED = "\033[1;31m"
    BOLD_GREEN = "\033[1;32m"
    BOLD_CYAN = "\033[1;36m"
    BOLD_MAGENTA = "\033[1;35m"
    # Cyber / neon accents (256-color; safe fallback still looks fine)
    NEON_GREEN = "\033[38;5;46m"
    NEON_CYAN = "\033[38;5;51m"
    NEON_PINK = "\033[38;5;201m"
    NEON_PURPLE = "\033[38;5;141m"
    ORANGE = "\033[38;5;208m"

    enabled = True


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    if not sys.stdout.isatty():
        return False
    if IS_WINDOWS:
        if _COLORAMA_AVAILABLE:
            # colorama.init() already wrapped stdout to translate ANSI codes
            # into Win32 calls — works on every Windows version, no further
            # checks needed.
            return True
        # No colorama installed: try enabling native VT100 processing
        # (Windows 10 1511+ only). Falls back to no-color if it fails
        # (older Windows or an unusual terminal).
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            if not kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING):
                return False
            return True
        except Exception:
            return False
    return os.environ.get("TERM", "") != "dumb"


def _c(text: str, *codes: str) -> str:
    if not Colors.enabled:
        return text
    return "".join(codes) + text + Colors.RESET


Colors.enabled = _supports_color()


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def banner(text: str) -> None:
    line = "═" * 72
    print("\n" + _c(line, Colors.ORANGE if hasattr(Colors, "ORANGE") else Colors.BOLD_RED))
    print(_c("  ◈  " + text, Colors.BOLD, Colors.BRIGHT_CYAN))
    print(_c(line, Colors.ORANGE if hasattr(Colors, "ORANGE") else Colors.BOLD_RED))


def ok(msg: str) -> None:
    # During an active tool HUD, the checklist already shows status — skip chatter
    try:
        from progress_ui import hud_active
        if hud_active() and VERBOSE < VERBOSE_DEBUG:
            return
    except Exception:
        pass
    # During pipeline at normal verbosity: only mission-critical OK lines
    if _PIPELINE is not None and VERBOSE < VERBOSE_DEBUG:
        low = msg.lower()
        keep = (
            "unique" in low
            or "mission" in low
            or "finished" in low
            or "responded" in low
            or "complete" in low
            or "loot" in low
            or low.startswith("stage ")
        )
        if not keep:
            return
    print(f"{_c('[OK]', Colors.BOLD_GREEN)}   {msg}")


def warn(msg: str) -> None:
    print(f"{_c('[WARN]', Colors.YELLOW)} ⚠  {msg}")


def fail(msg: str) -> None:
    print(f"{_c('[FAIL]', Colors.BOLD_RED)} ❌ {msg}")


def step(msg: str, phase: str | None = None) -> None:
    """
    Phase header. During a pipeline at normal verbosity, emit a single short
    deploy line (progress UI owns the rest).
    """
    key = (phase or "").strip().lower()
    if not key:
        low = msg.lower()
        for name in (
            "subdomains", "dns", "httpprobe", "tls", "crawl", "js", "params",
            "content", "xss", "sqli", "ssrf_ssti", "nuclei", "cloud", "screenshots",
        ):
            if name.replace("_", " ") in low or name in low:
                key = name
                break
        if not key:
            key = "default"

    # Quiet mission mode: ship banner is printed by PipelineProgress.begin_module
    # (unique hull per module). Skip the duplicate one-line deploy here.
    if _PIPELINE is not None and VERBOSE < VERBOSE_DEBUG:
        return

    try:
        from progress_ui import phase_banner, PHASE_TITLE
    except Exception:
        print(f"\n{_c('--->', Colors.BOLD_CYAN)} {_c(msg, Colors.BOLD)}")
        return
    phase_banner(key if key in PHASE_TITLE or key in (
        "subdomains", "dns", "httpprobe", "tls", "crawl", "js", "params",
        "content", "xss", "sqli", "ssrf_ssti", "nuclei", "cloud", "screenshots",
        "default", "pipeline",
    ) else "default", detail=msg if VERBOSE >= VERBOSE_DEBUG else "", verbose=VERBOSE)


def info(msg: str) -> None:
    """Info line — suppressed during pipeline at normal verbosity (progress UI owns scan)."""
    if _PIPELINE is not None and VERBOSE < VERBOSE_DEBUG:
        return
    if VERBOSE < VERBOSE_NORMAL:
        return
    try:
        from progress_ui import scan_log
        scan_log(msg, level="INF", frame=int(time.time() * 10) % 20, verbose=VERBOSE)
    except Exception:
        print(f"{_c('[INFO]', Colors.BRIGHT_BLUE)}  ℹ  {msg}")


# --------------------------------------------------------------------------- #
# Verbosity levels — set from --verbose / --debug / interactive shell
# --------------------------------------------------------------------------- #
#
#   0  QUIET  banners + ok/warn/fail only (no $ command echoes)
#   1  NORMAL default — $ commands + stage progress
#   2  DEBUG  + timing, exit codes, stderr snippets, stage file diffs
#   3  LIVE   + stream full stdout/stderr of every tool as it runs
#
VERBOSE_QUIET = 0
VERBOSE_NORMAL = 1
VERBOSE_DEBUG = 2
VERBOSE_LIVE = 3

VERBOSE_LABELS = {
    0: "quiet",
    1: "normal",
    2: "debug",
    3: "live",
}

VERBOSE = VERBOSE_NORMAL
DEBUG = False  # kept for back-compat; True when VERBOSE >= 2


def set_verbose(level: int | str) -> int:
    """Clamp and apply verbosity. Accepts int 0-3 or label names."""
    global VERBOSE, DEBUG
    if isinstance(level, str):
        key = level.strip().lower()
        rev = {v: k for k, v in VERBOSE_LABELS.items()}
        if key in rev:
            level = rev[key]
        else:
            try:
                level = int(key)
            except ValueError:
                raise ValueError(
                    f"Unknown verbose level '{level}'. Use 0-3 or: "
                    + ", ".join(VERBOSE_LABELS.values())
                )
    VERBOSE = max(VERBOSE_QUIET, min(VERBOSE_LIVE, int(level)))
    DEBUG = VERBOSE >= VERBOSE_DEBUG
    return VERBOSE


def verbose_at(level: int) -> bool:
    return VERBOSE >= level


def vprint(msg: str, min_level: int = VERBOSE_NORMAL) -> None:
    """Print only when current VERBOSE >= min_level."""
    if VERBOSE >= min_level:
        print(msg)


def debug(msg: str) -> None:
    """Prints when VERBOSE >= 2 (debug). Per-tool timing, exit codes,
    byte/line counts, stderr contents, and output previews."""
    if VERBOSE < VERBOSE_DEBUG:
        return
    for line in msg.splitlines() or [""]:
        print(f"{_c('[DEBUG]', Colors.BRIGHT_MAGENTA)} {line}")


def live(msg: str) -> None:
    """Prints when VERBOSE >= 3 (live). Full tool streams and pipe traffic."""
    if VERBOSE < VERBOSE_LIVE:
        return
    for line in msg.splitlines() or [""]:
        print(f"{_c('[LIVE]', Colors.NEON_GREEN)} {line}")


def _preview_lines(data: bytes, n: int = 5) -> str:
    lines = data.decode(errors="ignore").splitlines()
    shown = lines[:n]
    text = "\n".join(f"      {ln}" for ln in shown)
    if len(lines) > n:
        text += f"\n      ... ({len(lines) - n} more line(s))"
    return text or "      (empty)"


def _echo_cmd(cmd: list) -> None:
    # Suppress command echo while live HUD is painting (prevents progress spam)
    try:
        from progress_ui import hud_active
        if hud_active() and VERBOSE < VERBOSE_LIVE:
            return
    except Exception:
        pass
    if VERBOSE >= VERBOSE_NORMAL:
        print(_c(f"    $ {' '.join(str(c) for c in cmd)}", Colors.GRAY))


def which(binary: str) -> str | None:
    found = shutil.which(binary, path=os.environ.get("PATH", ""))
    if found:
        return found
    for extra_dir in EXTRA_PATH_DIRS:
        candidate = extra_dir / (binary + (".exe" if IS_WINDOWS else ""))
        if candidate.exists():
            return str(candidate)
    return None


def tool_env() -> dict:
    """Env vars merged in for every subprocess call so newly-installed tools
    are found even before the user's shell profile is updated."""
    path_prefix = os.pathsep.join(str(p) for p in EXTRA_PATH_DIRS)
    return {
        "GOPATH": str(GOPATH_DIR),
        "PATH": path_prefix + os.pathsep + os.environ.get("PATH", ""),
        # Keep tool output plain-text for files/index/dashboard (no [[35m…] codes).
        "NO_COLOR": "1",
        "CLICOLOR": "0",
        "FORCE_COLOR": "0",
    }


# ANSI / orphan SGR (e.g. dnsx colors that become [[35mCNAME[0m] in the UI)
_ANSI_RE = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
    r"|\x9B[0-?]*[ -/]*[@-~]"
    r"|\[(?:\d{1,3};){0,8}\d{1,3}m"
)


def strip_ansi(text: str) -> str:
    """Strip terminal color codes from tool output before writing scan files."""
    if not text:
        return ""
    s = _ANSI_RE.sub("", text)
    s = s.replace("\x1b", "").replace("\x9b", "")
    s = re.sub(r"[ \t]{2,}", " ", s)
    return s


def strip_ansi_bytes(data: bytes) -> bytes:
    if not data:
        return b""
    return strip_ansi(data.decode(errors="ignore")).encode("utf-8", errors="replace")


LOG_DIR = BASE_DIR / "logs"
DEBUG_LOG = LOG_DIR / "debug.log"


def _ensure_log_dir() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def _run_capture_live(cmd: list[str], env: dict, check: bool) -> subprocess.CompletedProcess:
    """Run a command capturing stdout/stderr while streaming both live (VERBOSE>=3).

    Interruptible: /stop kills the process group mid-run.
    """
    import threading
    from run_control import CONTROL, RunStopped

    popen_kwargs: dict = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "env": env,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        popen_kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **popen_kwargs)
    CONTROL.register(proc)
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stopped = False

    def _pump(stream, sink: list[bytes], tag: str) -> None:
        try:
            for raw in iter(stream.readline, b""):
                sink.append(raw)
                text = raw.decode(errors="ignore").rstrip("\r\n")
                print(f"{_c(f'[{tag}]', Colors.NEON_GREEN)} {text}")
        finally:
            try:
                stream.close()
            except Exception:
                pass

    t_out = threading.Thread(target=_pump, args=(proc.stdout, stdout_chunks, "out"), daemon=True)
    t_err = threading.Thread(target=_pump, args=(proc.stderr, stderr_chunks, "err"), daemon=True)
    t_out.start()
    t_err.start()
    try:
        while proc.poll() is None:
            if CONTROL.is_stopped():
                stopped = True
                CONTROL._kill_one(proc, force=True)
                CONTROL.kill_children()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    pass
                break
            try:
                CONTROL.check()
            except RunStopped:
                stopped = True
                CONTROL._kill_one(proc, force=True)
                break
            time.sleep(0.2)
    except KeyboardInterrupt:
        stopped = True
        CONTROL._stop.set()
        CONTROL._kill_one(proc, force=True)
        CONTROL.kill_children()
        CONTROL.kill_known_tools()
        raise RunStopped("run interrupted by Ctrl+C") from None
    finally:
        if proc.poll() is None:
            CONTROL._kill_one(proc, force=True)
            try:
                proc.wait(timeout=1)
            except Exception:
                pass
        CONTROL.unregister(proc, kill_if_alive=True)
    t_out.join(timeout=5)
    t_err.join(timeout=5)
    if stopped:
        raise RunStopped("run stopped by operator (/stop)")
    rc = proc.returncode if proc.returncode is not None else -1
    result = subprocess.CompletedProcess(
        cmd, rc, stdout=b"".join(stdout_chunks), stderr=b"".join(stderr_chunks)
    )
    if check and rc != 0:
        raise subprocess.CalledProcessError(rc, cmd, output=result.stdout, stderr=result.stderr)
    return result


def run(cmd: list[str], check: bool = False, env: dict | None = None,
        capture: bool = False) -> subprocess.CompletedProcess:
    """Run an external tool. Honors /pause and /stop (kills process group)."""
    from run_control import CONTROL, RunStopped, run_interruptible

    CONTROL.check()  # fail fast if already stopped
    _echo_cmd(cmd)
    merged_env = os.environ.copy()
    merged_env.update(tool_env())
    if env:
        merged_env.update(env)
    t0 = time.time()

    try:
        if capture:
            # Always PIPE stderr (rather than DEVNULL) so nothing is silently
            # lost — it's logged to DEBUG_LOG every time, echoed as preview when
            # VERBOSE>=2, and fully streamed live when VERBOSE>=3.
            if VERBOSE >= VERBOSE_LIVE:
                result = _run_capture_live(cmd, merged_env, check)
            else:
                result = run_interruptible(
                    cmd, env=merged_env, capture=True, check=check
                )
            elapsed = time.time() - t0

            _ensure_log_dir()
            with open(DEBUG_LOG, "a", encoding="utf-8", errors="replace") as logf:
                logf.write(f"\n$ {' '.join(str(c) for c in cmd)}  "
                           f"(exit={result.returncode}, {elapsed:.1f}s)\n")
                if result.stderr:
                    logf.write(result.stderr.decode(errors="ignore"))

            debug(f"exit={result.returncode}  time={elapsed:.1f}s  "
                  f"stdout={len(result.stdout or b'')}B  stderr={len(result.stderr or b'')}B")
            if result.stderr and result.stderr.strip():
                if VERBOSE < VERBOSE_LIVE:
                    debug("stderr:\n" + "\n".join(f"      {ln}" for ln in
                                                   result.stderr.decode(errors="ignore").splitlines()[:15]))
            if result.stdout and VERBOSE < VERBOSE_LIVE:
                debug("stdout preview:\n" + _preview_lines(result.stdout))
            return result

        # Non-capturing: still interruptible so /stop works
        result = run_interruptible(cmd, env=merged_env, capture=False, check=check)
        elapsed = time.time() - t0
        debug(f"exit={result.returncode}  time={elapsed:.1f}s  (live output above, not captured)")
        return result
    except RunStopped:
        warn("command interrupted by /stop")
        raise


def pipeline(commands: list[list[str]], input_data: bytes = b"") -> bytes:
    """Chain a list of argv commands, piping stdout->stdin, like a shell pipe
    but without invoking a shell (no injection risk from target strings).

    Each stage is interruptible — /stop kills the active process group.
    """
    from run_control import CONTROL, RunStopped, run_interruptible

    merged_env = os.environ.copy()
    merged_env.update(tool_env())
    data = input_data
    in_lines = len(data.decode(errors="ignore").splitlines())
    debug(f"pipeline start: {in_lines} input line(s)")

    for cmd in commands:
        CONTROL.check()
        binary = which(cmd[0])
        if not binary:
            warn(f"'{cmd[0]}' not found on PATH; skipping this stage of the pipeline.")
            debug(f"pipeline aborted: '{cmd[0]}' missing")
            return b""
        full_cmd = [binary] + cmd[1:]
        _echo_cmd(full_cmd)
        t0 = time.time()
        try:
            proc = run_interruptible(
                full_cmd, env=merged_env, capture=True, input_data=data
            )
        except RunStopped:
            warn(f"pipeline interrupted at {cmd[0]} by /stop")
            raise
        elapsed = time.time() - t0

        _ensure_log_dir()
        with open(DEBUG_LOG, "a", encoding="utf-8", errors="replace") as logf:
            logf.write(f"\n$ {' '.join(str(c) for c in full_cmd)} (piped, "
                       f"exit={proc.returncode}, {elapsed:.1f}s)\n")
            if proc.stderr:
                logf.write(proc.stderr.decode(errors="ignore"))

        out_lines = len((proc.stdout or b"").decode(errors="ignore").splitlines())
        debug(f"  -> {cmd[0]}: exit={proc.returncode}  time={elapsed:.1f}s  "
              f"{in_lines} line(s) in -> {out_lines} line(s) out")
        if proc.stderr and proc.stderr.strip():
            err_lines = proc.stderr.decode(errors="ignore").splitlines()
            if VERBOSE >= VERBOSE_LIVE:
                for ln in err_lines:
                    live(f"{cmd[0]}|err  {ln}")
            else:
                debug(f"     {cmd[0]} stderr:\n" + "\n".join(
                    f"        {ln}" for ln in err_lines[:10]))
        if VERBOSE >= VERBOSE_LIVE and proc.stdout:
            for ln in proc.stdout.decode(errors="ignore").splitlines()[:200]:
                live(f"{cmd[0]}|out  {ln}")
            total = out_lines
            if total > 200:
                live(f"{cmd[0]}|out  ... ({total - 200} more line(s) not shown)")
        if out_lines == 0 and in_lines > 0:
            debug(f"     ^ {cmd[0]} dropped all {in_lines} input line(s) to zero output — "
                  f"this is usually where a pipeline silently goes empty")

        data = strip_ansi_bytes(proc.stdout or b"")
        in_lines = out_lines
    return data


def ensure_dirs() -> None:
    for d in (BASE_DIR, WORDLIST_DIR, OUTPUT_DIR):
        d.mkdir(parents=True, exist_ok=True)


def write_lines(path: Path, data: bytes) -> int:
    text = strip_ansi(data.decode(errors="ignore"))
    lines = sorted(set(ln.strip() for ln in text.splitlines() if ln.strip()))
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(lines)


# --------------------------------------------------------------------------- #
# checkenv
# --------------------------------------------------------------------------- #

def is_admin() -> bool:
    try:
        if IS_WINDOWS:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def cmd_checkenv(_args) -> None:
    banner("Environment / Permission Check")
    label = lambda s: _c(s, Colors.BOLD)
    print(f"{label('OS           ')}: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"{label('Python       ')}: {sys.version.split()[0]} at {sys.executable}")
    print(f"{label('Home dir     ')}: {HOME}")
    admin = is_admin()
    admin_str = _c(str(admin), Colors.YELLOW) if admin else str(admin)
    print(f"{label('Elevated/root')}: {admin_str}")

    print("\nPermissions note:")
    print("  - Almost everything here (subfinder, httpx, nuclei, katana, ffuf, gau, ...)")
    print("    runs fine as a normal, non-admin user. Do not run this as root/Administrator.")
    print("  - Raw-socket scanning (naabu SYN mode, nmap -sS, masscan) needs root on")
    print("    Linux/macOS or Administrator + Npcap on Windows. Those specific tools will")
    print("    tell you if they need elevation.")

    banner("Prerequisite Tools")
    prereqs = {
        "git": "https://git-scm.com/downloads",
        "go": "https://go.dev/dl/",
        ("python" if IS_WINDOWS else "python3"): "https://www.python.org/downloads/",
        "cargo": "https://rustup.rs (optional — only needed for feroxbuster/findomain/x8)",
    }
    missing = []
    for tool, install_url in prereqs.items():
        path = which(tool)
        if path:
            ok(f"{tool} -> {path}")
        else:
            fail(f"{tool} not found. Install from: {install_url}")
            if tool != "cargo":
                missing.append(tool)

    print()
    if missing:
        print("Install the missing prerequisites above, then re-run `checkenv`.")
    else:
        print("All required prerequisites present. You can run `setup` next.")

    banner("Passive-source API keys (optional, but this is the #1 lever on subdomain yield)")
    print("subfinder/amass/chaos/github-subdomains use free sources with NO key. Each key")
    print("below unlocks additional passive-DNS sources and meaningfully increases how many")
    print("subdomains you'll find — a missing key here, not a timeout, is the usual reason")
    print("subdomain enumeration looks sparse.\n")
    for key, used_by in KNOWN_API_KEYS.items():
        if os.environ.get(key):
            ok(f"{key} is set -> enables {used_by}")
        else:
            warn(f"{key} not set -> {used_by} will be skipped/limited")
    print("\nSet these with:  python3 reconkit.py keys set <NAME> <value>")
    print(f"They're stored in {SECRETS_FILE} (permission-locked, never in this script's")
    print("source code) and loaded automatically on every run. See `keys --help`.")
    print("\nsubfinder also reads keys from its own config file instead of env vars for some")
    print("sources — see: ~/.config/subfinder/provider-config.yaml (Linux/macOS) or")
    print("%APPDATA%\\subfinder\\provider-config.yaml (Windows).")


# --------------------------------------------------------------------------- #
# setup
# --------------------------------------------------------------------------- #

def install_pip_tools() -> None:
    """Install Python recon CLIs once into the user environment.

    Uses `pip install --user` so tools live in the user site-packages and
    their scripts land in USER_SCRIPTS_DIR (e.g. ~/.local/bin on Linux).
    No project virtualenv — same "install once, keep forever" model as Go/Cargo.
    """
    print(f"Installing Python tools with pip --user "
          f"(scripts -> {USER_SCRIPTS_DIR}) ...")
    run([sys.executable, "-m", "pip", "install", "--user", "--upgrade", "pip"])
    result = run([sys.executable, "-m", "pip", "install", "--user", *PIP_TOOLS])
    if result.returncode != 0:
        # Debian/Ubuntu/Kali PEP 668: plain --user can still be blocked.
        warn("pip --user failed (common on externally-managed Python); "
             "retrying with --break-system-packages ...")
        result = run([
            sys.executable, "-m", "pip", "install", "--user",
            "--break-system-packages", *PIP_TOOLS,
        ])
    if result.returncode == 0:
        ok(f"Installed pip tools (user): {', '.join(PIP_TOOLS)}")
        ok(f"User script dir on PATH for this process: {USER_SCRIPTS_DIR}")
    else:
        warn("Some pip tools may have failed to install; see output above.")


def install_go_tools() -> None:
    go = which("go")
    if not go:
        fail("Go not found on PATH. Install from https://go.dev/dl/ then re-run setup.")
        return
    for module, binary in GO_TOOLS.items():
        print(f"Installing {binary} ...")
        result = run([go, "install", "-v", module])
        (ok if result.returncode == 0 else warn)(
            f"{binary} {'installed' if result.returncode == 0 else 'install returned non-zero exit'}"
        )


def install_cargo_tools() -> None:
    cargo = which("cargo")
    if not cargo:
        warn("cargo not found; skipping feroxbuster/findomain/x8 (optional). Install rustup to enable.")
        return
    for crate, binary in CARGO_TOOLS.items():
        print(f"Installing {binary} (cargo) ...")
        result = run([cargo, "install", crate])
        (ok if result.returncode == 0 else warn)(
            f"{binary} {'installed' if result.returncode == 0 else 'install returned non-zero exit'}"
        )


def setup_gf_patterns() -> None:
    git = which("git")
    if not git:
        warn("git not found; skipping gf pattern setup.")
        return
    GF_PATTERNS_DIR.mkdir(parents=True, exist_ok=True)
    dest = GF_PATTERNS_DIR / "Gf-Patterns"
    if dest.exists():
        ok(f"gf patterns already present at {dest}")
    else:
        print("Cloning gf patterns (xss/sqli/ssrf/ssti/lfi/redirect/rce) ...")
        result = run([git, "clone", "--depth", "1", GF_PATTERNS_REPO, str(dest)])
        if result.returncode == 0:
            for pattern_file in dest.glob("*.json"):
                shutil.copy(pattern_file, GF_PATTERNS_DIR / pattern_file.name)
            ok(f"gf patterns installed to {GF_PATTERNS_DIR}")
        else:
            warn("Failed to clone gf patterns.")


def update_nuclei_templates() -> None:
    nuclei = which("nuclei")
    if not nuclei:
        warn("nuclei not found; skipping template update.")
        return
    print("Updating nuclei templates ...")
    run([nuclei, "-update-templates"])
    ok("nuclei templates updated")


def load_config() -> dict:
    """Load ~/.reconkit/config.json if present; return empty dict on failure."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def resolve_nuclei_templates_dir() -> Path:
    """Return the nuclei templates root from config, else the default path."""
    configured = load_config().get("nuclei_templates")
    if configured:
        p = Path(str(configured)).expanduser()
        if p.is_dir():
            return p
    return NUCLEI_TEMPLATES_DIR


def resolve_nuclei_template_subdir(templates_dir: Path, *relative_candidates: str) -> Path | None:
    """Return the first existing template subdirectory under templates_dir.

    Modern nuclei-templates layout nests categories under protocol folders
    (e.g. http/cves). Older layouts kept them at the repo root (e.g. cves/).
    """
    for rel in relative_candidates:
        candidate = templates_dir / rel
        if candidate.is_dir():
            return candidate
    return None


def persist_env_instructions() -> None:
    banner("Persisting environment variables (manual, one-time step)")
    path_parts = [str(GO_BIN_DIR), str(CARGO_BIN_DIR), str(USER_SCRIPTS_DIR)]
    if IS_WINDOWS:
        path_suffix = ";".join(path_parts)
        print("PowerShell (current user, persists across sessions):")
        print(f'    [Environment]::SetEnvironmentVariable("GOPATH", "{GOPATH_DIR}", "User")')
        print(f'    [Environment]::SetEnvironmentVariable("Path", $env:Path + ";{path_suffix}", "User")')
        print("\nOr via cmd.exe:")
        print(f'    setx GOPATH "{GOPATH_DIR}"')
        print(f'    setx PATH "%PATH%;{path_suffix}"')
    else:
        shell_rc = "~/.zshrc" if IS_MACOS else "~/.bashrc"
        path_suffix = ":".join(path_parts)
        print(f"Add these lines to {shell_rc}:")
        print(f'    export GOPATH="{GOPATH_DIR}"')
        print(f'    export PATH="$PATH:{path_suffix}"')
        print(f"\nThen reload with: source {shell_rc}")
    print("\nThis script sets these for its own subprocess calls automatically, but")
    print("your interactive shell needs the step above to use tools directly.")


def write_config() -> None:
    ensure_dirs()
    config = {
        "created": datetime.now(timezone.utc).isoformat(),
        "platform": platform.system(),
        "gopath": str(GOPATH_DIR),
        "go_bin": str(GO_BIN_DIR),
        "cargo_bin": str(CARGO_BIN_DIR),
        "user_scripts": str(USER_SCRIPTS_DIR),
        "wordlists": str(WORDLIST_DIR),
        "output_dir": str(OUTPUT_DIR),
        "scope_file": str(SCOPE_FILE),
        "gf_patterns": str(GF_PATTERNS_DIR),
        "nuclei_templates": str(NUCLEI_TEMPLATES_DIR),
        "nuclei_severity": "critical,high,medium",
        "httpx_threads": 100,
        "katana_depth": 3,
    }
    CONFIG_FILE.write_text(json.dumps(config, indent=2))
    ok(f"Config written to {CONFIG_FILE}")

    if not SCOPE_FILE.exists():
        SCOPE_FILE.write_text(
            "# Add ONE authorized domain/host per line, e.g.:\n"
            "# example.com\n"
            "# *.example.com\n"
            "#\n"
            "# Only add targets you have explicit written authorization to test.\n"
            "# Use: python3 reconkit.py scope add <domain>\n"
        )
        ok(f"Scope file created at {SCOPE_FILE} (empty — add targets before running)")


def install_colorama_for_self() -> None:
    """Installs colorama into the SAME interpreter running this script
    (user site-packages), so raw ANSI color reliably works on older
    Windows terminals too. Best-effort — the script works fine without it
    on Windows 10+/Linux/macOS, just falls back to raw ANSI there."""
    if _COLORAMA_AVAILABLE:
        ok("colorama already available for this interpreter")
        return
    print("Installing colorama for better color support on older Windows terminals ...")
    result = run([sys.executable, "-m", "pip", "install", "--user", "colorama"])
    if result.returncode != 0:
        result = run([
            sys.executable, "-m", "pip", "install", "--user",
            "--break-system-packages", "colorama",
        ])
    if result.returncode == 0:
        ok("colorama installed. It will take effect the next time you run this script.")
    else:
        warn("Could not install colorama automatically. Color will still work via raw "
             "ANSI on Windows 10+/Linux/macOS; install manually with "
             f"'{sys.executable} -m pip install --user colorama' for older Windows terminals.")


def cmd_setup(_args) -> None:
    banner("Setup: Python/Go/Rust tools, gf patterns, nuclei templates, config")
    ensure_dirs()
    install_colorama_for_self()
    install_pip_tools()
    install_go_tools()
    install_cargo_tools()
    setup_gf_patterns()
    update_nuclei_templates()
    write_config()
    persist_env_instructions()

    banner("Setup complete")
    print("Next steps:")
    print("  1. Apply the PATH/env var instructions above to your shell.")
    print("  2. python3 reconkit.py verify")
    print("  3. python3 reconkit.py wordlists")
    print("  4. python3 reconkit.py scope add <your-authorized-domain>")
    print("  5. python3 reconkit.py run --target <your-authorized-domain>")
    legacy_venv = BASE_DIR / "venv"
    if legacy_venv.exists():
        print(f"\nNote: A leftover venv from older reconkit versions is at {legacy_venv}.")
        print("It is no longer used; you can delete it safely if you want the disk space back.")


# --------------------------------------------------------------------------- #
# wordlists
# --------------------------------------------------------------------------- #

def cmd_wordlists(_args) -> None:
    banner("Downloading wordlists")
    ensure_dirs()
    git = which("git")
    if not git:
        fail("git not found; cannot clone wordlist repos.")
        return

    for name, url in WORDLIST_TARGETS.items():
        dest = WORDLIST_DIR / name
        if dest.exists():
            ok(f"{name} already present at {dest}")
            continue
        print(f"Cloning {name} ...")
        result = run([git, "clone", "--depth", "1", url, str(dest)])
        (ok if result.returncode == 0 else warn)(f"{name} {'cloned' if result.returncode == 0 else 'clone failed'}")

    try:
        import urllib.request
        for url in RESOLVER_URLS:
            fname = url.rsplit("/", 1)[-1]
            dest = WORDLIST_DIR / fname
            print(f"Downloading {fname} ...")
            urllib.request.urlretrieve(url, dest)
            ok(f"Saved {dest}")
    except Exception as exc:
        warn(f"Resolver download failed: {exc}")

    print(f"\nWordlists directory: {WORDLIST_DIR}")


def default_content_wordlist() -> Path | None:
    candidates = [
        WORDLIST_DIR / "seclists" / "Discovery" / "Web-Content" / "raft-medium-directories.txt",
        WORDLIST_DIR / "onelistforall" / "onelistforallmicro.txt",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #

def cmd_verify(_args) -> None:
    banner("Verifying tool installation")
    all_tools = (list(GO_TOOLS.values()) + list(CARGO_TOOLS.values())
                 + PIP_TOOLS + ["git", "go", "cargo"])
    missing = []
    for tool in sorted(set(all_tools)):
        path = which(tool)
        if path:
            ok(f"{tool:<18} -> {path}")
        else:
            fail(f"{tool:<18} NOT FOUND")
            missing.append(tool)

    print()
    if missing:
        warn(f"{len(missing)} tool(s) missing: {', '.join(missing)}")
        print("Re-run `setup`, or install the missing tool manually, then re-verify.")
    else:
        ok("All expected tools are present.")


# --------------------------------------------------------------------------- #
# API key secrets — stored in a permission-locked file, never in this script
# --------------------------------------------------------------------------- #

_KEY_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_RESERVED_KEY_NAMES = frozenset({
    "set", "list", "remove", "get", "add", "delete", "keys", "key", "help",
})


def load_secrets_env() -> None:
    """Reads ~/.reconkit/secrets.env (KEY=value per line) and applies each
    to os.environ for THIS process only, if not already set by the shell.
    Called once at startup so every command sees these keys automatically —
    you never edit this script's source to configure a key."""
    if not SECRETS_FILE.exists():
        return
    for line in SECRETS_FILE.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        # Skip garbage lines from bad /keys set typos (e.g. set=PDCP_API_KEY)
        if not key or key.lower() in _RESERVED_KEY_NAMES:
            continue
        if not _KEY_NAME_RE.match(key):
            continue
        if key:
            os.environ.setdefault(key, value)


def _lock_down_secrets_file() -> None:
    """Restricts secrets.env to owner-read/write only. Best-effort: Windows
    ACLs work differently, so this is a no-op there (NTFS already defaults
    to only your account having access to your own profile folder)."""
    if IS_WINDOWS:
        return
    try:
        os.chmod(SECRETS_FILE, 0o600)
    except Exception:
        pass


def _read_secrets_map() -> dict[str, str]:
    """Parse secrets.env into {NAME: value}, ignoring comments and junk keys."""
    out: dict[str, str] = {}
    if not SECRETS_FILE.exists():
        return out
    for line in SECRETS_FILE.read_text(errors="ignore").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, _, value = raw.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if not key or key.lower() in _RESERVED_KEY_NAMES:
            continue
        if not _KEY_NAME_RE.match(key):
            continue
        out[key] = value
    return out


def _write_secrets_map(data: dict[str, str]) -> None:
    header = (
        "# API keys for optional passive-recon sources, one KEY=value per line.\n"
        "# Loaded automatically on every run. Never commit this file to git or\n"
        "# paste its contents anywhere — treat it exactly like a password file.\n"
        "#\n"
        "# Set via:  python reconkit.py keys set NAME value\n"
        "#       or: /keys set NAME value\n"
    )
    body = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))
    SECRETS_FILE.write_text(header + (body + "\n" if body else ""))
    _lock_down_secrets_file()


def cmd_keys(args) -> None:
    ensure_dirs()
    if not SECRETS_FILE.exists():
        _write_secrets_map({})

    if args.keys_action == "set":
        name = (args.name or "").strip()
        value = (args.value or "").strip().strip("'\"")
        if name.lower() in _RESERVED_KEY_NAMES or not _KEY_NAME_RE.match(name):
            fail(
                f"invalid key name {name!r}. Use UPPER_SNAKE like PDCP_API_KEY.\n"
                f"  correct:  python reconkit.py keys set PDCP_API_KEY <token>\n"
                f"            /keys set PDCP_API_KEY <token>\n"
                f"  wrong:    /keys set set PDCP_API_KEY <token>  (extra 'set')"
            )
            return
        if not value or value.lower() in _RESERVED_KEY_NAMES or value in ("/exit", "exit"):
            fail("missing or invalid key value — paste the token after the name.")
            return
        if name not in KNOWN_API_KEYS:
            warn(f"'{name}' isn't one of the keys this script looks for "
                 f"({', '.join(KNOWN_API_KEYS)}), but I'll store it anyway — "
                 f"it'll still be exported to the environment for any tool that reads it.")
        data = _read_secrets_map()
        data[name] = value
        _write_secrets_map(data)
        # Apply immediately for this process (and shell session if same process)
        os.environ[name] = value
        masked = value[:4] + "…" + value[-2:] if len(value) > 8 else "(set)"
        ok(f"Stored {name}={masked} in {SECRETS_FILE} (mode 600).")
        print("Tip: reload is automatic next run. For tools outside reconkit:")
        print(f"     export {name}='…'   # bash")
        print(f"     $env:{name}='…'     # PowerShell")

    elif args.keys_action == "list":
        load_secrets_env()
        data = _read_secrets_map()
        print(f"Secrets file: {SECRETS_FILE}\n")
        if not data and not any(os.environ.get(n) for n in KNOWN_API_KEYS):
            print("No secrets stored yet.")
            print("  /keys set PDCP_API_KEY <token>")
            print("  python reconkit.py keys set PDCP_API_KEY <token>")
            return
        # Known keys first
        for name, used_by in KNOWN_API_KEYS.items():
            val = data.get(name) or os.environ.get(name)
            if val:
                masked = val[:4] + "…" + val[-2:] if len(val) > 8 else "set"
                ok(f"{name} = {masked}  (enables {used_by})")
            else:
                warn(f"{name} not set  (would enable {used_by})")
        # Extra keys in file
        extras = sorted(k for k in data if k not in KNOWN_API_KEYS)
        if extras:
            print("\nOther keys in secrets.env:")
            for name in extras:
                val = data[name]
                masked = val[:4] + "…" + val[-2:] if len(val) > 8 else "set"
                print(f"  {name} = {masked}")

    elif args.keys_action == "remove":
        name = (args.name or "").strip()
        if not SECRETS_FILE.exists():
            print("No secrets file exists.")
            return
        data = _read_secrets_map()
        if name in data:
            del data[name]
            _write_secrets_map(data)
            os.environ.pop(name, None)
            ok(f"Removed {name} from {SECRETS_FILE}.")
        else:
            warn(f"{name} was not in {SECRETS_FILE}.")
            # still rewrite to scrub junk reserved keys
            _write_secrets_map(data)


# --------------------------------------------------------------------------- #
# scope management — the authorization gate
# --------------------------------------------------------------------------- #

def load_scope() -> set[str]:
    if not SCOPE_FILE.exists():
        return set()
    return {ln.strip() for ln in SCOPE_FILE.read_text().splitlines()
            if ln.strip() and not ln.strip().startswith("#")}


def in_scope(target: str) -> bool:
    scope = load_scope()
    if target in scope:
        return True
    for entry in scope:
        if entry.startswith("*.") and target.endswith(entry[1:]):
            return True
    return False


def cmd_scope(args) -> None:
    ensure_dirs()
    if not SCOPE_FILE.exists():
        write_config()

    if args.scope_action == "add":
        prompt = (
            f"Confirm you have EXPLICIT WRITTEN AUTHORIZATION to test "
            f"'{args.domain}' (bug bounty scope / signed pentest agreement / "
            f"your own infrastructure). Type 'yes' to confirm: "
        )
        confirm = input(_c(prompt, Colors.BOLD, Colors.YELLOW))
        if confirm.strip().lower() != "yes":
            print(_c("Not confirmed. Domain was NOT added.", Colors.YELLOW))
            return
        with open(SCOPE_FILE, "a") as f:
            f.write(args.domain.strip() + "\n")
        ok(f"Added '{args.domain}' to scope file: {SCOPE_FILE}")

    elif args.scope_action == "list":
        scope = load_scope()
        if not scope:
            print("Scope file is empty. Add a target with: reconkit.py scope add <domain>")
        else:
            print(f"Authorized targets in {SCOPE_FILE}:")
            for s in sorted(scope):
                print(f"  - {s}")

    elif args.scope_action == "check":
        if in_scope(args.domain):
            ok(f"'{args.domain}' IS in scope.")
        else:
            fail(f"'{args.domain}' is NOT in scope. Add it first with `scope add`.")


def require_scope_or_exit(target: str) -> None:
    banner("Authorization Gate")
    if not in_scope(target):
        fail(f"'{target}' is not in your scope file ({SCOPE_FILE}).")
        print("Add it first (after confirming authorization) with:")
        print(f"    python3 reconkit.py scope add {target}")
        sys.exit(1)
    ok(f"'{target}' confirmed in scope.")


# --------------------------------------------------------------------------- #
# Recon pipeline modules
# Each stage takes (target, outdir) and reads/writes plain text files under
# outdir. Every stage degrades gracefully (warns + skips) if its tool isn't
# installed, rather than crashing the whole run.
# --------------------------------------------------------------------------- #

def stage_subdomains(target: str, outdir: Path) -> Path:
    step("Subdomain enumeration (subfinder, amass, assetfinder, chaos, findomain, crt.sh, wayback, hackertarget)",
         phase="subdomains")
    subs_file = outdir / "subdomains.txt"
    target_lower = target.lower()
    collected: set[str] = set()

    def add(data: bytes):
        for ln in data.decode(errors="ignore").splitlines():
            ln = ln.strip().rstrip(".").lower()
            if ln:
                collected.add(ln)

    tools = [
        ("subfinder", ["-d", target, "-all", "-silent", "-timeout", "30"]),
        ("amass", ["enum", "-passive", "-d", target, "-timeout", "10"]),  # -timeout is in minutes
        ("assetfinder", ["-subs-only", target]),
        ("chaos", ["-d", target, "-silent"]),
        ("findomain", ["-t", target, "-q"]),
    ]
    # Passive web sources also shown on the checklist
    extra_tools = ["crt.sh", "wayback", "hackertarget"]
    checklist = None
    try:
        from progress_ui import tool_checklist
        checklist = tool_checklist(
            [t[0] for t in tools] + extra_tools,
            title=f"Subdomain enum · {target}",
            verbose=VERBOSE,
        )
    except Exception:
        checklist = None

    for binary, args in tools:
        path = which(binary)
        if not path:
            if checklist:
                checklist.finish_tool(binary, skipped=True, detail="not found")
            else:
                warn(f"{binary} not found; skipping.")
            continue
        if checklist:
            checklist.start_tool(binary)
        result = run([path] + args, capture=True)
        before = len(collected)
        add(result.stdout or b"")
        added = len(collected) - before
        if checklist:
            checklist.finish_tool(binary, added)
        elif added == 0:
            warn(f"{binary} returned 0 new subdomains — check {DEBUG_LOG} for its stderr "
                 f"(common causes: missing API key, rate limit, network block).")
        else:
            ok(f"{binary} contributed {added} new subdomain(s)")

    curl = which("curl")
    if curl:
        # Certificate transparency (crt.sh)
        if checklist:
            checklist.start_tool("crt.sh")
        before = len(collected)
        r = run([curl, "-s", "--max-time", "30", "--retry", "2",
                 f"https://crt.sh/?q=%25.{target}&output=json"], capture=True)
        try:
            entries = json.loads(r.stdout or b"[]")
            for e in entries:
                for name in str(e.get("name_value", "")).splitlines():
                    collected.add(name.replace("*.", "").strip().rstrip(".").lower())
        except Exception:
            if checklist is None:
                warn(f"crt.sh response wasn't valid JSON (likely rate-limited or timed out) — "
                     f"see {DEBUG_LOG}")
        if checklist:
            checklist.finish_tool("crt.sh", len(collected) - before)

        # Wayback machine
        if checklist:
            checklist.start_tool("wayback")
        before = len(collected)
        r = run([curl, "-s", "--max-time", "30", "--retry", "2",
                 f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=text&fl=original&collapse=urlkey"],
                capture=True)
        for ln in (r.stdout or b"").decode(errors="ignore").splitlines():
            host = re.sub(r"^https?://", "", ln).split("/")[0]
            if host:
                collected.add(host.rstrip(".").lower())
        if checklist:
            checklist.finish_tool("wayback", len(collected) - before)

        # HackerTarget passive DNS
        if checklist:
            checklist.start_tool("hackertarget")
        before = len(collected)
        r = run([curl, "-s", "--max-time", "20", "--retry", "1",
                 f"https://api.hackertarget.com/hostsearch/?q={target}"], capture=True)
        body = (r.stdout or b"").decode(errors="ignore")
        if "error" in body.lower() or "API count exceeded" in body:
            if checklist:
                checklist.finish_tool("hackertarget", skipped=True, detail="rate-limited")
            else:
                warn("HackerTarget API returned an error/rate-limit message — skipping its results.")
        else:
            for ln in body.splitlines():
                host = ln.split(",")[0].strip().rstrip(".").lower()
                if host and "." in host:
                    collected.add(host)
            if checklist:
                checklist.finish_tool("hackertarget", len(collected) - before)
    else:
        if checklist:
            for name in extra_tools:
                checklist.finish_tool(name, skipped=True, detail="curl missing")

    if checklist:
        checklist.stop(final_msg=f"Subdomain enum · {target}")

    collected = {h for h in collected if h.endswith(target_lower)}
    subs_file.write_text("\n".join(sorted(collected)) + ("\n" if collected else ""))
    ok(f"{len(collected)} unique subdomains -> {subs_file}")
    return subs_file


def stage_dns(target: str, outdir: Path, subs_file: Path) -> None:
    step("DNS intelligence (dnsx): records, CNAME takeover candidates", phase="dns")
    dnsx = which("dnsx")
    if not dnsx or not subs_file.exists():
        warn("dnsx not found or no subdomains file; skipping DNS stage.")
        return

    n_subs = len([ln for ln in subs_file.read_text(errors="ignore").splitlines() if ln.strip()])
    info(f"📡 resolving / fingerprinting {n_subs} host(s) via dnsx…")
    subs_data = subs_file.read_bytes()

    try:
        from progress_ui import tool_checklist
        cl = tool_checklist(
            ["dnsx-records", "dnsx-cname"],
            title=f"DNS · {n_subs} host(s)",
            verbose=VERBOSE,
        )
    except Exception:
        cl = None

    if cl:
        cl.start_tool("dnsx-records")
    records = pipeline([
        ["dnsx", "-silent", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-resp"],
    ], input_data=subs_data)
    n_rec = len([ln for ln in records.decode(errors="ignore").splitlines() if ln.strip()])
    if cl:
        cl.finish_tool("dnsx-records", n_rec)
    # Always plain text (no color escapes) for indexer / dashboard.
    (outdir / "dns_records.txt").write_bytes(strip_ansi_bytes(records))
    ok(f"DNS records -> {outdir / 'dns_records.txt'}")

    if cl:
        cl.start_tool("dnsx-cname")
    cname_out = pipeline([["dnsx", "-silent", "-cname", "-resp-only"]], input_data=subs_data)
    takeover_candidates = [
        ln for ln in strip_ansi(cname_out.decode(errors="ignore")).splitlines()
        if ln.strip() and any(fp in ln.lower() for fp in CNAME_TAKEOVER_FINGERPRINTS)
    ]
    if cl:
        cl.finish_tool("dnsx-cname", len(takeover_candidates))
        cl.stop(final_msg=f"DNS · {n_subs} host(s)")
    (outdir / "cname_takeover_candidates.txt").write_text(
        "\n".join(takeover_candidates) + ("\n" if takeover_candidates else ""),
        encoding="utf-8",
    )
    ok(f"{len(takeover_candidates)} possible CNAME-takeover candidates -> "
       f"{outdir / 'cname_takeover_candidates.txt'} (verify manually before reporting)")


def stage_httpprobe(subs_file: Path, outdir: Path) -> Path:
    step("Live host probing (httpx)", phase="httpprobe")
    alive_file = outdir / "alive.txt"
    if not which("httpx") or not subs_file.exists():
        warn("httpx not found or no subdomains file; skipping.")
        alive_file.write_text("")
        return alive_file
    input_count = len([ln for ln in subs_file.read_text(errors="ignore").splitlines() if ln.strip()])
    info(f"📡 probing {input_count} host(s) with httpx (threads=50)…")
    try:
        from progress_ui import tool_checklist
        cl = tool_checklist(["httpx"], title=f"HTTP probe · {input_count} host(s)", verbose=VERBOSE)
        cl.start_tool("httpx")
    except Exception:
        cl = None
    result = pipeline([
        ["httpx", "-silent", "-threads", "50", "-timeout", "15", "-retries", "2",
         "-title", "-status-code", "-tech-detect", "-follow-redirects"],
    ], input_data=subs_file.read_bytes())
    alive_file.write_bytes(result)
    n = len(result.decode(errors="ignore").splitlines())
    if cl:
        cl.finish_tool("httpx", n)
        cl.stop(final_msg=f"HTTP probe · {input_count} host(s)")
    ok(f"{n}/{input_count} hosts responded -> {alive_file}")
    if input_count and n / input_count < 0.2:
        warn(f"Only {n} of {input_count} hosts responded — check {DEBUG_LOG} for httpx's "
             f"stderr. Common causes: the target's WAF/CDN rate-limiting this many "
             f"concurrent probes, or most subdomains genuinely being dead/parked. Try "
             f"re-running with fewer threads if you suspect rate-limiting.")
    return alive_file


def stage_tls(alive_file: Path, outdir: Path) -> None:
    step("TLS / JARM recon (tlsx)", phase="tls")
    tlsx = which("tlsx")
    if not tlsx or not alive_file.exists():
        warn("tlsx not found or no alive-hosts file; skipping.")
        return
    host_list = [ln.split()[0] for ln in alive_file.read_bytes().splitlines() if ln.strip()]
    info(f"🔐 TLS recon on {len(host_list)} alive host(s)…")
    hosts = b"\n".join(host_list)
    try:
        from progress_ui import tool_checklist
        cl = tool_checklist(["tlsx"], title=f"TLS · {len(host_list)} host(s)", verbose=VERBOSE)
        cl.start_tool("tlsx")
    except Exception:
        cl = None
    result = pipeline([
        ["tlsx", "-silent", "-json", "-so", "-expired",
         "-self-signed", "-mismatched", "-tls-version", "-jarm"],
    ], input_data=hosts)
    n = len([ln for ln in result.decode(errors="ignore").splitlines() if ln.strip()])
    if cl:
        cl.finish_tool("tlsx", n)
        cl.stop(final_msg=f"TLS · {len(host_list)} host(s)")
    (outdir / "tls_recon.json").write_bytes(result)
    ok(f"TLS recon -> {outdir / 'tls_recon.json'}")


def stage_crawl(alive_file: Path, outdir: Path) -> Path:
    step("Crawling & URL discovery (katana, gospider, hakrawler, gau, waybackurls)", phase="crawl")
    urls_file = outdir / "urls.txt"
    if not alive_file.exists():
        warn("No alive-hosts file; skipping crawl.")
        urls_file.write_text("")
        return urls_file

    alive_data = alive_file.read_bytes()
    hosts = [ln.split()[0] for ln in alive_data.decode(errors="ignore").splitlines() if ln.strip()]
    collected: set[str] = set()
    info(f"🕷️ crawling {len(hosts)} host(s)…")

    crawl_tools = ["katana", "gospider", "hakrawler", "gau", "waybackurls"]
    checklist = None
    try:
        from progress_ui import tool_checklist
        checklist = tool_checklist(
            crawl_tools,
            title=f"Crawl · {len(hosts)} host(s)",
            verbose=VERBOSE,
        )
    except Exception:
        checklist = None

    katana = which("katana")
    if katana and hosts:
        if checklist:
            checklist.start_tool("katana")
        before = len(collected)
        clean_input = ("\n".join(hosts) + "\n").encode()
        result = pipeline([["katana", "-silent", "-d", "3", "-jc", "-kf", "all"]], input_data=clean_input)
        collected.update(result.decode(errors="ignore").splitlines())
        if checklist:
            checklist.finish_tool("katana", len(collected) - before)
    else:
        if checklist:
            checklist.finish_tool("katana", skipped=True, detail="not found" if not katana else "no hosts")
        elif not katana:
            warn("katana not found; skipping.")

    def _host_loop(tool_name: str, subset: list[str], runner):
        if not subset:
            return 0
        before = len(collected)
        for host in subset:
            runner(host)
        return len(collected) - before

    gospider = which("gospider")
    if gospider and hosts:
        if checklist:
            checklist.start_tool("gospider")
        def _gs(host):
            r = run([gospider, "-s", host, "-c", "10", "-d", "3", "-q"], capture=True)
            collected.update(_extract_urls((r.stdout or b"").decode(errors="ignore")))
        added = _host_loop("gospider", hosts[:25], _gs)
        if checklist:
            checklist.finish_tool("gospider", added)
    else:
        if checklist:
            checklist.finish_tool("gospider", skipped=True, detail="not found" if not gospider else "no hosts")
        elif not gospider:
            warn("gospider not found; skipping.")

    hakrawler = which("hakrawler")
    if hakrawler and hosts:
        if checklist:
            checklist.start_tool("hakrawler")
        def _hk(host):
            r = pipeline([["hakrawler", "-d", "3", "-subs", "-u"]], input_data=(host + "\n").encode())
            collected.update(r.decode(errors="ignore").splitlines())
        added = _host_loop("hakrawler", hosts[:25], _hk)
        if checklist:
            checklist.finish_tool("hakrawler", added)
    else:
        if checklist:
            checklist.finish_tool("hakrawler", skipped=True, detail="not found" if not hakrawler else "no hosts")
        elif not hakrawler:
            warn("hakrawler not found; skipping.")

    gau = which("gau")
    if gau and hosts:
        if checklist:
            checklist.start_tool("gau")
        def _gau(host):
            r = run([gau, "--threads", "10", host], capture=True)
            collected.update((r.stdout or b"").decode(errors="ignore").splitlines())
        added = _host_loop("gau", hosts[:25], _gau)
        if checklist:
            checklist.finish_tool("gau", added)
    else:
        if checklist:
            checklist.finish_tool("gau", skipped=True, detail="not found" if not gau else "no hosts")
        elif not gau:
            warn("gau not found; skipping.")

    waybackurls = which("waybackurls")
    if waybackurls and hosts:
        if checklist:
            checklist.start_tool("waybackurls")
        def _wb(host):
            r = run([waybackurls, host], capture=True)
            collected.update((r.stdout or b"").decode(errors="ignore").splitlines())
        added = _host_loop("waybackurls", hosts[:25], _wb)
        if checklist:
            checklist.finish_tool("waybackurls", added)
    else:
        if checklist:
            checklist.finish_tool("waybackurls", skipped=True,
                                  detail="not found" if not waybackurls else "no hosts")
        elif not waybackurls:
            warn("waybackurls not found; skipping.")

    if checklist:
        checklist.stop(final_msg=f"Crawl · {len(hosts)} host(s)")

    uro = which("uro")
    collected = {u.strip() for u in collected if u.strip()}
    if uro and collected:
        deduped = pipeline([["uro"]], input_data="\n".join(collected).encode())
        urls_file.write_bytes(deduped)
        n = len(deduped.decode(errors="ignore").splitlines())
    else:
        urls_file.write_text("\n".join(sorted(collected)) + ("\n" if collected else ""))
        n = len(collected)
    ok(f"{n} unique URLs -> {urls_file}")
    return urls_file


def stage_js(urls_file: Path, outdir: Path) -> Path:
    step("JavaScript recon: discovery + read-only secret/endpoint extraction", phase="js")
    js_file = outdir / "js_urls.txt"
    if not urls_file.exists():
        warn("No urls file; skipping JS stage.")
        js_file.write_text("")
        return js_file

    urls = [u for u in urls_file.read_text(errors="ignore").splitlines() if u.strip()]
    js_urls = sorted({u for u in urls if re.search(r"\.js(\?|$)", u)})
    js_file.write_text("\n".join(js_urls) + ("\n" if js_urls else ""))
    ok(f"{len(js_urls)} JS files -> {js_file}")

    curl = which("curl")
    if not curl or not js_urls:
        if not curl:
            warn("curl not found; skipping secret extraction from JS.")
        return js_file

    findings: dict[str, set[str]] = {k: set() for k in JS_SECRET_PATTERNS}
    scan_list = js_urls[:200]
    try:
        from progress_ui import HostProgress
        hp = HostProgress("JS fetch/secrets", total=len(scan_list), phase="js", verbose=VERBOSE)
    except Exception:
        hp = None
    for u in scan_list:  # sane cap for a single run
        if hp:
            hp.advance(u)
        r = run([curl, "-s", "-k", "--max-time", "10", u], capture=True)
        body = (r.stdout or b"").decode(errors="ignore")
        for name, pattern in JS_SECRET_PATTERNS.items():
            for m in re.findall(pattern, body):
                findings[name].add(m if isinstance(m, str) else m[0])
    if hp:
        hp.close()

    secrets_file = outdir / "js_secrets_and_endpoints.json"
    secrets_file.write_text(json.dumps({k: sorted(v) for k, v in findings.items() if v}, indent=2))
    total = sum(len(v) for v in findings.values())
    ok(f"{total} candidate secrets/endpoints across {len([k for k,v in findings.items() if v])} "
       f"categories -> {secrets_file} (verify manually; these are pattern matches, not confirmed leaks)")
    return js_file


def stage_params(urls_file: Path, outdir: Path) -> None:
    step("Parameter discovery (arjun, x8, unfurl)", phase="params")
    if not urls_file.exists():
        warn("No urls file; skipping.")
        return
    urls_data = urls_file.read_bytes()
    try:
        from progress_ui import tool_checklist
        cl = tool_checklist(["unfurl", "arjun"], title="Parameter mining", verbose=VERBOSE)
    except Exception:
        cl = None

    unfurl = which("unfurl")
    if unfurl:
        if cl:
            cl.start_tool("unfurl")
        keys = pipeline([["unfurl", "keys"]], input_data=urls_data)
        n = write_lines(outdir / "param_names.txt", keys)
        if cl:
            cl.finish_tool("unfurl", n)
        ok(f"Parameter names -> {outdir / 'param_names.txt'}")
    else:
        if cl:
            cl.finish_tool("unfurl", skipped=True, detail="not found")
        warn("unfurl not found; skipping param-name extraction.")

    arjun = which("arjun")
    if arjun:
        if cl:
            cl.start_tool("arjun")
        run([arjun, "-i", str(urls_file), "-oT", str(outdir / "arjun_params.txt"), "--stable"])
        hits = 0
        try:
            p = outdir / "arjun_params.txt"
            if p.exists():
                hits = sum(1 for ln in p.read_text(errors="ignore").splitlines() if ln.strip())
        except Exception:
            hits = 0
        if cl:
            cl.finish_tool("arjun", hits)
        ok(f"arjun hidden-parameter results -> {outdir / 'arjun_params.txt'}")
    else:
        if cl:
            cl.finish_tool("arjun", skipped=True, detail="not found")
        warn("arjun not found; skipping hidden-parameter mining.")
    if cl:
        cl.stop(final_msg="Parameter mining")


def stage_content_discovery(alive_file: Path, outdir: Path, wordlist: Path | None) -> None:
    step("Content discovery: sensitive-path checks + directory fuzzing", phase="content")
    if not alive_file.exists():
        warn("No alive-hosts file; skipping.")
        return

    try:
        from progress_ui import HostProgress
    except Exception:
        HostProgress = None  # type: ignore

    httpx = which("httpx")
    if httpx:
        hosts = [ln.split()[0] for ln in alive_file.read_text(errors="ignore").splitlines() if ln.strip()]
        subset = hosts[:25]
        sensitive_hits = []
        hp = HostProgress("sensitive paths", total=len(subset), phase="content", verbose=VERBOSE) if HostProgress else None
        for host in subset:
            if hp:
                hp.advance(host)
            # httpx -path expects stdin of hosts; feed one at a time to keep output attributable
            r = pipeline([["httpx", "-silent", "-mc", "200", "-path", ",".join(SENSITIVE_PATHS)]],
                         input_data=(host + "\n").encode())
            sensitive_hits.extend(r.decode(errors="ignore").splitlines())
        if hp:
            hp.close()
        write_lines(outdir / "sensitive_paths_found.txt", "\n".join(sensitive_hits).encode())
        ok(f"Sensitive-path checks -> {outdir / 'sensitive_paths_found.txt'}")
    else:
        warn("httpx not found; skipping sensitive-path checks.")

    ffuf = which("ffuf")
    if ffuf and wordlist:
        hosts = [ln.split()[0] for ln in alive_file.read_text(errors="ignore").splitlines() if ln.strip()]
        subset = hosts[:10]
        hp = HostProgress("ffuf fuzz", total=len(subset), phase="content", verbose=VERBOSE) if HostProgress else None
        for host in subset:  # cap: fuzzing is heavy, don't blast an entire large scope unattended
            if hp:
                hp.advance(host)
            out_json = outdir / f"ffuf_{re.sub(r'[^A-Za-z0-9]+', '_', host)}.json"
            run([ffuf, "-u", f"{host}/FUZZ", "-w", str(wordlist), "-mc", "200,301,302,403",
                 "-ac", "-t", "50", "-o", str(out_json), "-of", "json"])
        if hp:
            hp.close()
        ok(f"ffuf directory fuzzing results -> {outdir}/ffuf_*.json")
    elif not ffuf:
        warn("ffuf not found; skipping directory fuzzing.")
    else:
        warn("No wordlist available; run `wordlists` first. Skipping directory fuzzing.")


def stage_xss(urls_file: Path, outdir: Path) -> None:
    step("XSS detection (gf patterns + kxss reflection check + dalfox)", phase="xss")
    if not urls_file.exists():
        warn("No urls file; skipping.")
        return
    urls_data = urls_file.read_bytes()
    n_urls = len([ln for ln in urls_data.decode(errors="ignore").splitlines() if ln.strip()])
    info(f"💉 XSS pipeline on {n_urls} URL(s)…")
    try:
        from progress_ui import tool_checklist
        cl = tool_checklist(["gf-xss", "kxss", "dalfox"], title=f"XSS · {n_urls} URL(s)", verbose=VERBOSE)
    except Exception:
        cl = None

    gf = which("gf")
    xss_candidates = urls_data
    if gf:
        if cl:
            cl.start_tool("gf-xss")
        xss_candidates = pipeline([["gf", "xss"]], input_data=urls_data) or urls_data
        n = len([ln for ln in xss_candidates.decode(errors="ignore").splitlines() if ln.strip()])
        if cl:
            cl.finish_tool("gf-xss", n)
    else:
        if cl:
            cl.finish_tool("gf-xss", skipped=True, detail="not found")
        warn("gf not found (or patterns missing); using full URL list for XSS checks instead.")

    kxss = which("kxss")
    if kxss and xss_candidates.strip():
        if cl:
            cl.start_tool("kxss")
        reflected = pipeline([["kxss"]], input_data=xss_candidates)
        lines = [ln for ln in reflected.decode(errors="ignore").splitlines() if "Not Reflected" not in ln]
        write_lines(outdir / "xss_reflected_params.txt", "\n".join(lines).encode())
        if cl:
            cl.finish_tool("kxss", len(lines))
        ok(f"Reflected-parameter candidates -> {outdir / 'xss_reflected_params.txt'}")
    else:
        if cl:
            cl.finish_tool("kxss", skipped=True, detail="not found" if not kxss else "no candidates")
        warn("kxss not found; skipping reflection check.")

    dalfox = which("dalfox")
    if dalfox and xss_candidates.strip():
        if cl:
            cl.start_tool("dalfox")
        uro = which("uro")
        piped = pipeline([["uro"]], input_data=xss_candidates) if uro else xss_candidates
        result = pipeline([["dalfox", "pipe", "--silence", "--skip-bav"]], input_data=piped)
        (outdir / "dalfox_results.txt").write_bytes(result)
        n = len([ln for ln in result.decode(errors="ignore").splitlines() if ln.strip()])
        if cl:
            cl.finish_tool("dalfox", n)
        ok(f"dalfox results -> {outdir / 'dalfox_results.txt'}")
    else:
        if cl:
            cl.finish_tool("dalfox", skipped=True, detail="not found" if not dalfox else "no candidates")
        warn("dalfox not found; skipping active XSS scan.")
    if cl:
        cl.stop(final_msg=f"XSS · {n_urls} URL(s)")


def stage_sqli(urls_file: Path, outdir: Path) -> None:
    step("SQL injection detection (non-destructive canaries: error/boolean/time-based signals)",
         phase="sqli")
    if not urls_file.exists():
        warn("No urls file; skipping.")
        return
    urls_data = urls_file.read_bytes()
    try:
        from progress_ui import tool_checklist
        cl = tool_checklist(
            ["gf-sqli", "error-canary", "boolean-canary"],
            title="SQLi canaries",
            verbose=VERBOSE,
        )
    except Exception:
        cl = None

    gf = which("gf")
    if cl:
        cl.start_tool("gf-sqli")
    candidates = pipeline([["gf", "sqli"]], input_data=urls_data) if gf else urls_data
    n_cand = len([ln for ln in candidates.decode(errors="ignore").splitlines() if ln.strip()])
    if cl:
        if gf:
            cl.finish_tool("gf-sqli", n_cand)
        else:
            cl.finish_tool("gf-sqli", skipped=True, detail="not found")
    if not gf:
        warn("gf not found (or patterns missing); using full URL list instead.")
    if not candidates.strip():
        if cl:
            cl.finish_tool("error-canary", skipped=True, detail="no candidates")
            cl.finish_tool("boolean-canary", skipped=True, detail="no candidates")
            cl.stop(final_msg="SQLi canaries")
        ok("No SQLi-shaped parameters found.")
        return

    qsreplace = which("qsreplace")
    httpx = which("httpx")
    if not (qsreplace and httpx):
        if cl:
            cl.finish_tool("error-canary", skipped=True, detail="tools missing")
            cl.finish_tool("boolean-canary", skipped=True, detail="tools missing")
            cl.stop(final_msg="SQLi canaries")
        warn("qsreplace/httpx not found; skipping SQLi detection.")
        write_lines(outdir / "sqli_candidates.txt", candidates)
        return

    if cl:
        cl.start_tool("error-canary")
    errors = pipeline([["qsreplace", "'"], ["httpx", "-silent", "-ms", "error|sql|syntax|mysql|postgresql|oracle"]],
                       input_data=candidates)
    n_err = write_lines(outdir / "sqli_error_based.txt", errors)
    if cl:
        cl.finish_tool("error-canary", n_err)

    if cl:
        cl.start_tool("boolean-canary")
    boolean = pipeline([["qsreplace", "1' AND '1'='1"], ["httpx", "-silent", "-mc", "200"]], input_data=candidates)
    n_bool = write_lines(outdir / "sqli_boolean_based.txt", boolean)
    if cl:
        cl.finish_tool("boolean-canary", n_bool)
        cl.stop(final_msg="SQLi canaries")

    ok(f"SQLi detection results -> {outdir / 'sqli_error_based.txt'}, {outdir / 'sqli_boolean_based.txt'}")
    print("      (This is detection only — candidate vectors, not confirmed/exploited")
    print("       vulnerabilities. Time-based/UNION/full exploitation is intentionally")
    print("       out of scope for this toolkit; verify manually before reporting.)")


def stage_ssrf_ssti(urls_file: Path, outdir: Path) -> None:
    step("SSRF / SSTI detection (safe canaries only — no live command execution)",
         phase="ssrf_ssti")
    if not urls_file.exists():
        warn("No urls file; skipping.")
        return
    urls_data = urls_file.read_bytes()
    n_urls = len([ln for ln in urls_data.decode(errors="ignore").splitlines() if ln.strip()])
    info(f"🌐 SSRF/SSTI canaries across {n_urls} URL(s)…")
    gf = which("gf")
    qsreplace = which("qsreplace")
    httpx = which("httpx")
    try:
        from progress_ui import tool_checklist
        cl = tool_checklist(
            ["ssrf-metadata", "ssti-math"],
            title=f"SSRF/SSTI · {n_urls} URL(s)",
            verbose=VERBOSE,
        )
    except Exception:
        cl = None
    if not (qsreplace and httpx):
        if cl:
            cl.finish_tool("ssrf-metadata", skipped=True, detail="tools missing")
            cl.finish_tool("ssti-math", skipped=True, detail="tools missing")
            cl.stop()
        warn("qsreplace/httpx not found; skipping SSRF/SSTI detection.")
        return

    ssrf_candidates = pipeline([["gf", "ssrf"]], input_data=urls_data) if gf else urls_data
    if ssrf_candidates.strip():
        if cl:
            cl.start_tool("ssrf-metadata")
        # AWS metadata read-only probe — detection only, no credential use.
        metadata_hits = pipeline([
            ["qsreplace", "http://169.254.169.254/latest/meta-data/"],
            ["httpx", "-silent", "-match-string", "ami-id"],
        ], input_data=ssrf_candidates)
        n = write_lines(outdir / "ssrf_metadata_candidates.txt", metadata_hits)
        if cl:
            cl.finish_tool("ssrf-metadata", n)
        ok(f"SSRF (cloud-metadata) candidates -> {outdir / 'ssrf_metadata_candidates.txt'}")
    else:
        if cl:
            cl.finish_tool("ssrf-metadata", skipped=True, detail="no candidates")

    ssti_candidates = pipeline([["gf", "ssti"]], input_data=urls_data) if gf else urls_data
    if ssti_candidates.strip():
        if cl:
            cl.start_tool("ssti-math")
        arithmetic_hits = pipeline([
            ["qsreplace", "{{7*7}}"],
            ["httpx", "-silent", "-match-string", "49"],
        ], input_data=ssti_candidates)
        n = write_lines(outdir / "ssti_candidates.txt", arithmetic_hits)
        if cl:
            cl.finish_tool("ssti-math", n)
        ok(f"SSTI arithmetic-canary candidates -> {outdir / 'ssti_candidates.txt'} "
           f"(confirm manually — false positives possible)")
    else:
        if cl:
            cl.finish_tool("ssti-math", skipped=True, detail="no candidates")
    if cl:
        cl.stop(final_msg=f"SSRF/SSTI · {n_urls} URL(s)")


def stage_nuclei(alive_file: Path, subs_file: Path, outdir: Path) -> None:
    step("Vulnerability scanning (nuclei): CVEs, takeovers, exposed panels, misconfigurations",
         phase="nuclei")
    nuclei = which("nuclei")
    if not nuclei:
        warn("nuclei not found; skipping.")
        return
    target_list = alive_file if alive_file.exists() and alive_file.stat().st_size else subs_file
    if not target_list.exists():
        warn("No target list available for nuclei; skipping.")
        return
    n_t = len([ln for ln in target_list.read_text(errors="ignore").splitlines() if ln.strip()])
    info(f"💣 nuclei striking {n_t} host(s)…")
    # scan_activity wraps each nuclei pack below

    # Bare relative names like "cves/" resolve against CWD, not nuclei's
    # template store — that yields "no templates provided for scan". Always
    # pass absolute paths under the installed templates directory.
    templates_dir = resolve_nuclei_templates_dir()
    if not templates_dir.is_dir():
        warn(f"Nuclei templates not found at {templates_dir}; "
             f"run 'nuclei -update-templates' or 'python3 reconkit.py setup'.")
        return

    cfg = load_config()
    general_severity = str(cfg.get("nuclei_severity") or "critical,high,medium")

    # Prefer modern layout (http/<category>), fall back to legacy root dirs.
    cve_dir = resolve_nuclei_template_subdir(templates_dir, "http/cves", "cves")
    takeover_dir = resolve_nuclei_template_subdir(templates_dir, "http/takeovers", "takeovers")
    panels_dir = resolve_nuclei_template_subdir(
        templates_dir, "http/exposed-panels", "exposed-panels"
    )
    misconfig_dir = resolve_nuclei_template_subdir(
        templates_dir, "http/misconfiguration", "misconfiguration"
    )
    # General severity scan: prefer http/ (web targets), else full template root.
    general_dir = resolve_nuclei_template_subdir(templates_dir, "http") or templates_dir

    scans: list[tuple[str, list[str]]] = []
    if cve_dir:
        scans.append(
            ("nuclei_cve.txt", ["-t", str(cve_dir), "-severity", "critical,high"])
        )
    else:
        warn(f"CVE templates not found under {templates_dir}; skipping nuclei_cve.")

    if takeover_dir:
        scans.append(("nuclei_takeovers.txt", ["-t", str(takeover_dir)]))
    else:
        warn(f"Takeover templates not found under {templates_dir}; "
             f"skipping nuclei_takeovers.")

    if panels_dir:
        scans.append(("nuclei_exposed_panels.txt", ["-t", str(panels_dir)]))
    else:
        warn(f"Exposed-panel templates not found under {templates_dir}; "
             f"skipping nuclei_exposed_panels.")

    if misconfig_dir:
        scans.append(
            ("nuclei_misconfig.txt",
             ["-t", str(misconfig_dir), "-severity", "high,critical"])
        )
    else:
        warn(f"Misconfiguration templates not found under {templates_dir}; "
             f"skipping nuclei_misconfig.")

    scans.append(
        ("nuclei_general.txt",
         ["-t", str(general_dir), "-severity", general_severity])
    )

    # Compact tool list instead of one dual-bar HUD per nuclei pack
    pack_names = [fname.replace("nuclei_", "").replace(".txt", "") for fname, _ in scans]
    checklist = None
    try:
        from progress_ui import tool_checklist
        checklist = tool_checklist(
            pack_names,
            title=f"Nuclei · {n_t} host(s)",
            verbose=VERBOSE,
        )
    except Exception:
        checklist = None

    for (fname, extra_args), pack in zip(scans, pack_names):
        out_path = outdir / fname
        if checklist:
            checklist.start_tool(pack)
        run([nuclei, "-l", str(target_list), "-silent", "-o", str(out_path)] + extra_args)
        hits = 0
        try:
            if out_path.exists():
                hits = sum(1 for ln in out_path.read_text(errors="ignore").splitlines() if ln.strip())
        except Exception:
            hits = 0
        if checklist:
            checklist.finish_tool(pack, hits)
        else:
            ok(f"{fname} -> {out_path}")
    if checklist:
        checklist.stop(final_msg=f"Nuclei · {n_t} host(s)")


def stage_cloud(urls_file: Path, outdir: Path) -> None:
    step("Cloud storage exposure (S3 / Azure / GCP / Firebase) — read-only checks",
         phase="cloud")
    if not urls_file.exists():
        warn("No urls file; skipping.")
        return
    try:
        from progress_ui import tool_checklist, HostProgress
        cl = tool_checklist(
            ["extract-refs", "s3-list-check"],
            title="Cloud asset hunt",
            verbose=VERBOSE,
        )
    except Exception:
        cl = None
        HostProgress = None  # type: ignore

    if cl:
        cl.start_tool("extract-refs")
    text = urls_file.read_text(errors="ignore")
    s3 = sorted(set(re.findall(JS_SECRET_PATTERNS["s3_buckets"], text)))
    azure = sorted(set(re.findall(JS_SECRET_PATTERNS["azure_blobs"], text)))
    gcp = sorted(set(re.findall(JS_SECRET_PATTERNS["gcp_buckets"], text)))
    firebase = sorted(set(re.findall(JS_SECRET_PATTERNS["firebase_urls"], text)))
    n_refs = len(s3) + len(azure) + len(gcp) + len(firebase)
    (outdir / "cloud_assets.json").write_text(json.dumps(
        {"s3": s3, "azure_blobs": azure, "gcp_buckets": gcp, "firebase": firebase}, indent=2))
    if cl:
        cl.finish_tool("extract-refs", n_refs)
    ok(f"Cloud asset references -> {outdir / 'cloud_assets.json'}")

    aws = which("aws")
    if aws and s3:
        if cl:
            cl.start_tool("s3-list-check")
        open_buckets = []
        subset = s3[:25]
        # Nested host loop progress only if checklist not owning the HUD
        hp = None
        if HostProgress and not cl:
            hp = HostProgress("S3 list check", total=len(subset), phase="cloud", verbose=VERBOSE)
        for bucket in subset:
            if hp:
                hp.advance(bucket)
            bucket_name = bucket.split(".s3")[0].replace("s3://", "")
            r = run([aws, "s3", "ls", f"s3://{bucket_name}", "--no-sign-request"], capture=True)
            if r.returncode == 0:
                open_buckets.append(bucket_name)
        if hp:
            hp.close()
        write_lines(outdir / "open_s3_buckets.txt", "\n".join(open_buckets).encode())
        if cl:
            cl.finish_tool("s3-list-check", len(open_buckets))
        if open_buckets:
            ok(f"{len(open_buckets)} publicly LISTABLE S3 bucket(s) -> {outdir / 'open_s3_buckets.txt'}")
    else:
        if cl:
            cl.finish_tool(
                "s3-list-check",
                skipped=True,
                detail="aws missing" if not aws else "no s3 refs",
            )
        if not aws:
            warn("AWS CLI not found; skipping S3 public-listing check (bucket names still recorded above).")
    if cl:
        cl.stop(final_msg="Cloud asset hunt")


def stage_screenshots(alive_file: Path, outdir: Path) -> None:
    step("Screenshots (gowitness)", phase="screenshots")
    gowitness = which("gowitness")
    if not gowitness or not alive_file.exists():
        warn("gowitness not found or no alive-hosts file; skipping.")
        return
    n = len([ln for ln in alive_file.read_text(errors="ignore").splitlines() if ln.strip()])
    info(f"📸 capturing {n} host(s)…")
    shots_dir = outdir / "screenshots"
    shots_dir.mkdir(exist_ok=True)
    try:
        from progress_ui import tool_checklist
        cl = tool_checklist(["gowitness"], title=f"Screenshots · {n} host(s)", verbose=VERBOSE)
        cl.start_tool("gowitness")
    except Exception:
        cl = None
    run([gowitness, "file", "-f", str(alive_file), "-P", str(shots_dir), "--no-http"])
    if cl:
        cl.finish_tool("gowitness", n)
        cl.stop(final_msg=f"Screenshots · {n} host(s)")
    ok(f"Screenshots -> {shots_dir}")


# --------------------------------------------------------------------------- #
# run — wires all stages together, gated by scope
# --------------------------------------------------------------------------- #

ALL_MODULES = [
    "subdomains", "dns", "httpprobe", "tls", "crawl", "js",
    "params", "content", "xss", "sqli", "ssrf_ssti", "nuclei", "cloud", "screenshots",
]

MODULE_DESCRIPTIONS = {
    "subdomains": "subfinder, amass, assetfinder, chaos, findomain, crt.sh, Wayback, HackerTarget -> merged/deduped",
    "dns": "dnsx multi-record lookup (A/AAAA/CNAME/MX/NS/TXT) + CNAME-takeover fingerprint check",
    "httpprobe": "httpx: alive hosts, title, status code, tech-detect",
    "tls": "tlsx: cert details, expired/self-signed/mismatched certs, JARM fingerprint",
    "crawl": "katana, gospider, hakrawler, gau, waybackurls -> merged, deduped URLs",
    "js": "Finds .js files, extracts secrets/endpoints via regex (read-only)",
    "params": "unfurl (parameter names) + arjun (hidden parameter mining)",
    "content": "Sensitive-path checks + ffuf directory fuzzing",
    "xss": "gf xss -> kxss (reflection check) -> dalfox (candidate detection only)",
    "sqli": "gf sqli -> error/boolean-based detection canaries (non-destructive)",
    "ssrf_ssti": "Cloud-metadata SSRF probe + {{7*7}} SSTI canary (detection only)",
    "nuclei": "CVE, takeover, exposed-panel, misconfiguration, and general scans",
    "cloud": "S3/Azure/GCP/Firebase reference extraction + read-only S3 public-listing check",
    "screenshots": "gowitness screenshots of all alive hosts",
}


def cmd_modules(_args) -> None:
    banner("Available recon modules")
    name_width = max(len(m) for m in ALL_MODULES)
    for m in ALL_MODULES:
        print(f"  {_c(m.ljust(name_width), Colors.BOLD, Colors.CYAN)}  {MODULE_DESCRIPTIONS.get(m, '')}")
    print(f"\nRun all:      python3 reconkit.py run --target <domain>")
    print(f"Run selected: python3 reconkit.py run --target <domain> --modules "
          f"{','.join(ALL_MODULES[:3])}")


def _snapshot_outdir(outdir: Path) -> dict:
    snap = {}
    if not outdir.exists():
        return snap
    for p in outdir.rglob("*"):
        if p.is_file():
            try:
                lines = sum(1 for _ in p.open("rb")) if p.suffix in (".txt", ".json") else None
                snap[str(p.relative_to(outdir))] = (p.stat().st_size, lines)
            except Exception:
                pass
    return snap


# Active pipeline progress (set in cmd_run)
_PIPELINE: object | None = None


def run_stage(name: str, outdir: Path, func, *args, **kwargs):
    """Wraps a stage_* call with cyber phase progress, timing, and file diffs.

    Always publishes live_mission phase updates so the dashboard tracks
    /run, /agent, and any other caller of run_stage.
    """
    global _PIPELINE
    try:
        from run_control import CONTROL, RunStopped
        CONTROL.check()
    except Exception as e:
        if e.__class__.__name__ == "RunStopped":
            raise
        RunStopped = None  # type: ignore

    debug(f"=== STAGE START: {name} ===")
    # Dashboard telemetry — even when PipelineProgress is not installed (agents)
    try:
        from live_mission import begin_phase
        begin_phase(name, outdir=outdir)
    except Exception:
        pass
    if _PIPELINE is not None:
        try:
            _PIPELINE.begin_module(name)  # type: ignore[attr-defined]
        except Exception as e:
            if e.__class__.__name__ == "RunStopped":
                raise
    t0 = time.time()
    before = _snapshot_outdir(outdir) if VERBOSE >= VERBOSE_DEBUG else {}
    try:
        result = func(*args, **kwargs)
    except Exception as e:
        if _PIPELINE is not None:
            try:
                _PIPELINE.end_module(name, time.time() - t0)  # type: ignore[attr-defined]
            except Exception:
                pass
        try:
            from live_mission import end_phase
            end_phase(name, elapsed=time.time() - t0)
        except Exception:
            pass
        if e.__class__.__name__ == "RunStopped":
            warn(f"stage {name} interrupted by /stop")
        raise
    elapsed = time.time() - t0
    if _PIPELINE is not None:
        try:
            _PIPELINE.end_module(name, elapsed)  # type: ignore[attr-defined]
        except Exception:
            pass
    try:
        from live_mission import end_phase
        end_phase(name, elapsed=elapsed)
    except Exception:
        pass
    if VERBOSE >= VERBOSE_DEBUG:
        after = _snapshot_outdir(outdir)
        changed = {f: after[f] for f in after if after.get(f) != before.get(f)}
        debug(f"=== STAGE END: {name} ({elapsed:.1f}s) ===")
        if changed:
            for fname, (size, lines) in sorted(changed.items()):
                line_info = f"{lines} lines, " if lines is not None else ""
                debug(f"    wrote {fname}: {line_info}{size} bytes")
        else:
            debug("    (no files created or changed by this stage)")
    elif VERBOSE >= VERBOSE_NORMAL:
        ok(f"stage {name} finished in {elapsed:.1f}s")
    return result


def cmd_run(args) -> None:
    global _PIPELINE
    target = args.target.strip()
    require_scope_or_exit(target)

    modules = ALL_MODULES if args.modules == "all" else [m.strip() for m in args.modules.split(",")]
    unknown = set(modules) - set(ALL_MODULES)
    if unknown:
        fail(f"Unknown module(s): {', '.join(unknown)}. Valid: {', '.join(ALL_MODULES)}")
        sys.exit(1)

    ensure_dirs()
    outdir = OUTPUT_DIR / target.replace("*", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    # Always seed live tracker before stages (dashboard polls this file).
    # source= distinguishes /run /quick /full /scan /playbook /agent /cli
    source = str(getattr(args, "source", None) or "pipeline").strip() or "pipeline"
    try:
        from live_mission import start_run
        start_run(target=target, modules=list(modules), outdir=outdir, source=source)
    except Exception:
        pass

    try:
        from progress_ui import PipelineProgress
        _PIPELINE = PipelineProgress(modules=list(modules), verbose=VERBOSE, target=target)
        _PIPELINE.start()
    except Exception:
        _PIPELINE = None
        banner(f"Recon pipeline: {target}  (modules: {', '.join(modules)})")

    info(f"verbosity={VERBOSE} ({VERBOSE_LABELS.get(VERBOSE, '?')}) · outdir={outdir}")
    try:
        from run_control import CONTROL
        CONTROL.reset(label=f"run:{target}")
    except Exception:
        pass

    subs_file = outdir / "subdomains.txt"
    alive_file = outdir / "alive.txt"
    urls_file = outdir / "urls.txt"
    wordlist = default_content_wordlist()

    try:
        _cmd_run_stages(
            modules, target, outdir, subs_file, alive_file, urls_file, wordlist
        )
    except Exception as e:
        if e.__class__.__name__ == "RunStopped":
            warn("pipeline stopped by operator (/stop)")
        else:
            raise

    if _PIPELINE is not None:
        try:
            _PIPELINE.finish(str(outdir))  # type: ignore[attr-defined]
        except Exception:
            banner("Done")
            print(f"All output saved under: {outdir}")
    else:
        banner("Done")
        print(f"All output saved under: {outdir}")
    try:
        from live_mission import finish_run
        from run_control import CONTROL
        if CONTROL.is_stopped():
            from live_mission import mark_stopped
            mark_stopped()
        else:
            finish_run(ok=True, outdir=str(outdir))
    except Exception:
        pass
    _PIPELINE = None


def _cmd_run_stages(modules, target, outdir, subs_file, alive_file, urls_file, wordlist):
    """Inner stage sequence — may raise RunStopped."""
    if "subdomains" in modules:
        subs_file = run_stage("subdomains", outdir, stage_subdomains, target, outdir)
    elif not subs_file.exists():
        subs_file.write_text(target + "\n")  # fall back to root target only

    if "dns" in modules:
        run_stage("dns", outdir, stage_dns, target, outdir, subs_file)

    if "httpprobe" in modules:
        alive_file = run_stage("httpprobe", outdir, stage_httpprobe, subs_file, outdir)
    elif not alive_file.exists():
        alive_file.write_text("")

    if "tls" in modules:
        run_stage("tls", outdir, stage_tls, alive_file, outdir)

    if "crawl" in modules:
        urls_file = run_stage("crawl", outdir, stage_crawl, alive_file, outdir)
    elif not urls_file.exists():
        urls_file.write_text("")

    if "js" in modules:
        run_stage("js", outdir, stage_js, urls_file, outdir)

    if "params" in modules:
        run_stage("params", outdir, stage_params, urls_file, outdir)

    if "content" in modules:
        run_stage("content", outdir, stage_content_discovery, alive_file, outdir, wordlist)

    if "xss" in modules:
        run_stage("xss", outdir, stage_xss, urls_file, outdir)

    if "sqli" in modules:
        run_stage("sqli", outdir, stage_sqli, urls_file, outdir)

    if "ssrf_ssti" in modules:
        run_stage("ssrf_ssti", outdir, stage_ssrf_ssti, urls_file, outdir)

    if "nuclei" in modules:
        run_stage("nuclei", outdir, stage_nuclei, alive_file, subs_file, outdir)

    if "cloud" in modules:
        run_stage("cloud", outdir, stage_cloud, urls_file, outdir)

    if "screenshots" in modules:
        run_stage("screenshots", outdir, stage_screenshots, alive_file, outdir)


# --------------------------------------------------------------------------- #
# argparse wiring
# --------------------------------------------------------------------------- #

def cmd_shell(_args) -> None:
    """Launch the cyber interactive shell (v3.0.0)."""
    from shell import ReconShell
    ReconShell(
        verbose=VERBOSE,
        target=getattr(_args, "target", "") or "",
    ).run()


def cmd_dashboard(args) -> None:
    """Launch the local cyber findings dashboard."""
    from dashboard.server import run_server
    run_server(
        host=args.host,
        port=args.port,
        open_browser=not args.no_browser,
        refresh=not args.no_refresh,
    )


def cmd_findings(args) -> None:
    """CLI for findings index."""
    from findings.indexer import get_or_build_index, index_all_targets, index_target
    from findings.store import INDEX_FILE

    action = (args.action or "summary").lower()
    if action in ("reindex", "rebuild", "index"):
        info("indexing output directories…")
        payload = index_all_targets(persist=True)
        ok(
            f"{payload.get('target_count', 0)} target(s), "
            f"{payload.get('finding_count', 0)} finding(s) → {INDEX_FILE}"
        )
        return

    target = (args.target or "").strip()
    if target:
        summary, findings = index_target(target)
        banner(f"Findings: {target}")
        print(f"  count:    {summary.finding_count}")
        print(f"  modules:  {summary.by_module}")
        print(f"  severity: {summary.by_severity}")
        hot = [f for f in findings if f.severity in ("critical", "high", "medium")][:20]
        for f in hot:
            print(f"  [{f.severity}] {f.module}: {f.asset[:100]}")
        return

    payload = get_or_build_index(refresh=False)
    banner("Findings index")
    print(f"  generated: {payload.get('generated_at') or '(run: reconkit.py findings reindex)'}")
    print(f"  targets:   {payload.get('target_count', 0)}")
    print(f"  findings:  {payload.get('finding_count', 0)}")
    print(f"  file:      {INDEX_FILE}")
    for name, tinfo in sorted((payload.get("targets") or {}).items()):
        print(f"    • {name}: {tinfo.get('finding_count', 0)}")


def cmd_prove(args) -> None:
    """Safe validation layer — delegates to recon_prove."""
    from recon_prove import main as prove_main

    action = (getattr(args, "prove_action", None) or "policy").strip()
    argv: list[str] = [action]
    if action == "queue":
        if args.target:
            argv += ["--target", args.target]
        if getattr(args, "all", False):
            argv.append("--all")
        if getattr(args, "limit", None):
            argv += ["--limit", str(args.limit)]
        if getattr(args, "technique", None):
            argv += ["--technique", args.technique]
    elif action == "run":
        if not args.target:
            fail("prove run requires --target")
            sys.exit(2)
        argv += ["--target", args.target]
        if getattr(args, "all", False):
            argv.append("--all")
        if getattr(args, "limit", None):
            argv += ["--limit", str(args.limit)]
        if getattr(args, "technique", None):
            argv += ["--technique", args.technique]
        if getattr(args, "dry_run", False):
            argv.append("--dry-run")
    elif action == "list":
        if args.target:
            argv += ["--target", args.target]
    elif action == "show":
        if not args.target or not getattr(args, "proof_id", ""):
            fail("prove show requires --target and --id")
            sys.exit(2)
        argv += ["--target", args.target, "--id", args.proof_id]
    # policy / techniques: no extra args
    prove_main(argv)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            f"reconkit v{__version__} — Cross-platform authorized bug-bounty "
            "recon setup & runner. Prefer `python recon_shell.py` for the "
            "interactive cyber prompt."
        ),
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Shortcut for --verbose 2 (timing, exit codes, stderr previews). "
             "Must come before the subcommand.",
    )
    parser.add_argument(
        "-v", "--verbose", type=int, default=None, metavar="LEVEL",
        choices=[0, 1, 2, 3],
        help="Verbosity: 0=quiet, 1=normal (default), 2=debug, 3=live tool streams. "
             "Must come before the subcommand.",
    )
    parser.add_argument(
        "--version", action="version", version=f"reconkit {__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("checkenv", help="Check OS, permissions, and prerequisites").set_defaults(func=cmd_checkenv)
    sub.add_parser("setup", help="Install tools, gf patterns, write config").set_defaults(func=cmd_setup)
    sub.add_parser("wordlists", help="Download SecLists / OneListForAll / resolvers").set_defaults(func=cmd_wordlists)
    sub.add_parser("verify", help="Verify tools are on PATH").set_defaults(func=cmd_verify)

    scope_parser = sub.add_parser("scope", help="Manage your authorized-target scope file")
    scope_sub = scope_parser.add_subparsers(dest="scope_action", required=True)
    add_p = scope_sub.add_parser("add", help="Add an authorized target")
    add_p.add_argument("domain")
    scope_sub.add_parser("list", help="List authorized targets")
    check_p = scope_sub.add_parser("check", help="Check if a target is in scope")
    check_p.add_argument("domain")
    scope_parser.set_defaults(func=cmd_scope)

    run_parser = sub.add_parser("run", help="Run the recon pipeline against an in-scope target")
    run_parser.add_argument("--target", required=True, help="Target domain (must already be in scope)")
    run_parser.add_argument("--modules", default="all",
                             help=f"Comma-separated modules to run, or 'all'. Options: {', '.join(ALL_MODULES)}")
    run_parser.set_defaults(func=cmd_run)

    modules_parser = sub.add_parser("modules", help="List available recon modules and what each does")
    modules_parser.set_defaults(func=cmd_modules)

    keys_parser = sub.add_parser("keys", help="Manage optional API keys (stored in ~/.reconkit/secrets.env)")
    keys_sub = keys_parser.add_subparsers(dest="keys_action", required=True)
    keys_set_p = keys_sub.add_parser("set", help="Store an API key")
    keys_set_p.add_argument("name", help=f"One of: {', '.join(KNOWN_API_KEYS)}")
    keys_set_p.add_argument("value")
    keys_sub.add_parser("list", help="List which keys are set (values masked)")
    keys_remove_p = keys_sub.add_parser("remove", help="Remove a stored key")
    keys_remove_p.add_argument("name")
    keys_parser.set_defaults(func=cmd_keys)

    shell_parser = sub.add_parser(
        "shell",
        help="Launch the cyber-themed interactive prompt (slash commands, scan picker)",
    )
    shell_parser.add_argument("--target", default="", help="Pre-select target in the shell")
    shell_parser.set_defaults(func=cmd_shell)

    dash_parser = sub.add_parser(
        "dashboard",
        help="Launch local cyber web UI for findings (filter by target/module/severity)",
    )
    dash_parser.add_argument(
        "--host", default="0.0.0.0",
        help="Bind address (default 0.0.0.0 for VM/host access; use 127.0.0.1 for local only)",
    )
    dash_parser.add_argument("--port", type=int, default=8787)
    dash_parser.add_argument("--no-browser", action="store_true")
    dash_parser.add_argument("--no-refresh", action="store_true", help="Skip reindex on start")
    dash_parser.set_defaults(func=cmd_dashboard)

    findings_parser = sub.add_parser(
        "findings",
        help="Build or show unified findings index from ~/.reconkit/output",
    )
    findings_parser.add_argument(
        "action", nargs="?", default="summary",
        help="summary | reindex  (default: summary)",
    )
    findings_parser.add_argument("target", nargs="?", default="", help="Optional target for summary")
    findings_parser.set_defaults(func=cmd_findings)

    prove_parser = sub.add_parser(
        "prove",
        help="Safe validation (queue/run) against findings — no destructive exploits",
    )
    prove_sub = prove_parser.add_subparsers(dest="prove_action", required=True)
    prove_sub.add_parser("policy", help="Show prove policy").set_defaults(func=cmd_prove)
    prove_sub.add_parser("techniques", help="List safe validators").set_defaults(func=cmd_prove)
    pq = prove_sub.add_parser("queue", help="Build queue from findings index")
    pq.add_argument("--target", default="")
    pq.add_argument("--limit", type=int, default=None)
    pq.add_argument("--technique", default="")
    pq.add_argument("--all", action="store_true")
    pq.set_defaults(func=cmd_prove)
    pr = prove_sub.add_parser("run", help="Run safe validators")
    pr.add_argument("--target", required=True)
    pr.add_argument("--limit", type=int, default=None)
    pr.add_argument("--technique", default="")
    pr.add_argument("--all", action="store_true")
    pr.add_argument("--dry-run", action="store_true")
    pr.set_defaults(func=cmd_prove)
    pl = prove_sub.add_parser("list", help="List saved proofs")
    pl.add_argument("--target", default="")
    pl.set_defaults(func=cmd_prove)
    ps = prove_sub.add_parser("show", help="Show one proof")
    ps.add_argument("--target", required=True)
    ps.add_argument("--id", dest="proof_id", required=True)
    ps.set_defaults(func=cmd_prove)

    return parser


def main(argv: list[str] | None = None) -> None:
    load_secrets_env()
    parser = build_parser()
    args = parser.parse_args(argv)

    # Resolve verbosity: explicit -v wins; else --debug → 2; else default 1
    if args.verbose is not None:
        set_verbose(args.verbose)
    elif args.debug:
        set_verbose(VERBOSE_DEBUG)
    else:
        set_verbose(VERBOSE_NORMAL)

    if VERBOSE >= VERBOSE_DEBUG:
        _ensure_log_dir()
        debug(
            f"verbose={VERBOSE} ({VERBOSE_LABELS.get(VERBOSE, '?')}) — "
            f"everything also logged to {DEBUG_LOG}"
        )
    args.func(args)


if __name__ == "__main__":
    main()
