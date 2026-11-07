#!/usr/bin/env python3
"""One entry point for reconkit. Everything else lives in src/.

  python recon.py example.com
  python recon.py example.com --modules dns,httpprobe
  python recon.py example.com --resume
  python recon.py playbook list

The target must already be in ~/.reconkit/scope.txt.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

USAGE = """\
reconkit

Scan an authorized target (default: subdomains, dns, httpprobe, tls, wellknown, crawl):
  python recon.py <target>
  python recon.py <target> --modules dns,httpprobe
  python recon.py <target> all
  python recon.py <target> --resume
  python recon.py <target> --review

Setup:
  python recon.py setup
  python recon.py scope add <target>
  python recon.py scope list

Results:
  python recon.py findings <target>
  python recon.py prove <target>
  python recon.py notable --target <target>
  python recon.py playbook list
  python recon.py rate stealth
  python recon.py set RECON_AMASS_TIMEOUT 900
  python recon.py view <target>

Agents:
  python recon.py agents
  python recon.py agents <target>

  python recon.py help <command>
  python recon.py --version

The target must already be in ~/.reconkit/scope.txt.
Output is ~/.reconkit/output/<target>/.
"""

COMMANDS = {
    "checkenv",
    "setup",
    "wordlists",
    "verify",
    "scope",
    "run",
    "modules",
    "keys",
    "view",
    "findings",
    "prove",
    "notable",
    "diff",
    "report",
    "playbook",
    "rate",
    "set",
    "doctor",
    "tips",
    "critic",
    "eval",
    "inbox",
    "program",
    "graph",
    "session",
    "har",
    "evidence",
    "wordlist-target",
    "agents",
}
PROVE_ACTIONS = {"policy", "techniques", "queue", "run", "list", "show"}
AGENT_COMMANDS = {"providers", "run", "agents", "modules", "check-llm", "config"}
FINDINGS_ACTIONS = {"summary", "reindex"}


def looks_like_target(token: str) -> bool:
    if not token or token.startswith("-") or token in COMMANDS:
        return False
    if token.lower() in {"all", "help", "localhost"}:
        return token.lower() == "localhost"
    if " " in token or "/" in token or "\\" in token:
        return False
    if token.startswith("*."):
        return True
    if "." in token:
        return True
    parts = token.split(".")
    if parts and all(part.isdigit() for part in parts):
        return True
    return False


def looks_like_modules(token: str) -> bool:
    if not token or token.startswith("-"):
        return False
    if token == "all":
        return True
    pieces = token.split(",")
    if not pieces or any(not piece for piece in pieces):
        return False
    for piece in pieces:
        if piece != piece.lower() or not piece.replace("_", "").isalnum():
            return False
    return True


def _with_target(args: list[str]) -> list[str]:
    """example.com [modules] [flags] -> --target example.com [--modules ...] [flags]."""
    if not args or args[0].startswith("-"):
        return args
    if "--target" in args or "--scope-all" in args:
        return args
    if not looks_like_target(args[0]):
        return args
    out = ["--target", args[0]]
    rest = args[1:]
    if rest and looks_like_modules(rest[0]) and "--modules" not in rest:
        out.extend(["--modules", rest[0]])
        rest = rest[1:]
    return out + rest


def _target_then_value(args: list[str], value_flag: str | None) -> list[str]:
    if not args or args[0].startswith("-") or "--target" in args:
        return args
    if not looks_like_target(args[0]):
        return args
    out = ["--target", args[0]]
    rest = args[1:]
    if value_flag and rest and not rest[0].startswith("-") and value_flag not in rest:
        out.extend([value_flag, rest[0]])
        rest = rest[1:]
    return out + rest


def normalize_prove(args: list[str]) -> list[str]:
    tail = args[1:]
    if not tail:
        return ["prove", "techniques"]
    action = tail[0]
    if action not in PROVE_ACTIONS:
        if looks_like_target(action):
            return ["prove", "run", *_target_then_value(tail, "--technique")]
        return args
    body = tail[1:]
    if action == "run":
        body = _target_then_value(body, "--technique")
    elif action == "show":
        body = _target_then_value(body, "--id")
    elif action in {"queue", "list"}:
        body = _target_then_value(body, None)
    return ["prove", action, *body]


def normalize_agents(tail: list[str]) -> list[str]:
    if not tail:
        return ["agents"]
    if tail[0] not in AGENT_COMMANDS and looks_like_target(tail[0]):
        return ["run", *_with_target(tail)]
    if tail[0] == "run":
        return ["run", *_with_target(tail[1:])]
    return tail


def normalize_recon(args: list[str]) -> list[str] | None:
    if not args:
        return None
    if looks_like_target(args[0]):
        return ["run", *_with_target(args)]
    command = args[0]
    if command not in COMMANDS or command == "agents":
        return None
    if command == "run":
        return ["run", *_with_target(args[1:])]
    if command == "prove":
        return normalize_prove(args)
    if command == "findings":
        tail = args[1:]
        if len(tail) == 1 and looks_like_target(tail[0]):
            return ["findings", "summary", tail[0]]
        return args
    if command == "view":
        tail = args[1:]
        if tail and looks_like_target(tail[0]) and "--target" not in tail:
            return [command, "--target", tail[0], *tail[1:]]
        return args
    return args


def hoist_verbose(args: list[str]) -> tuple[list[str], list[str]]:
    """Pull -v/--debug/--version to the front. reconkit only accepts them there."""
    front: list[str] = []
    rest: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--debug" or token == "--version":
            front.append(token)
            index += 1
            continue
        if token in ("-v", "--verbose") and index + 1 < len(args):
            front.extend((token, args[index + 1]))
            index += 2
            continue
        rest.append(token)
        index += 1
    return front, rest


def prepare(argv: list[str]) -> tuple[str, list[str]]:
    """Return (kind, argv) for usage, error, help, agents, or recon."""
    if not argv or argv in (["-h"], ["--help"], ["help"]):
        return "usage", []
    if argv[0] == "help":
        return "help", argv[1:]

    front, rest = hoist_verbose(argv)
    if not rest:
        if "--version" in front:
            return "recon", front
        return "usage", []

    if rest[0] in ("-h", "--help", "help") and len(rest) == 1:
        return "usage", []

    if rest[0] == "agents":
        normalized = normalize_agents(rest[1:])
        if front and normalized and normalized[0] == "run":
            normalized = [*normalized, *front]
        elif front and normalized == ["agents"]:
            return "error", ["-v applies to a scan, not to the agent list."]
        return "agents", normalized

    normalized = normalize_recon(rest)
    if normalized is None:
        return "error", [f"Unknown command: {rest[0]}"]
    return "recon", [*front, *normalized]


def print_usage() -> None:
    print(USAGE, end="")


def main() -> None:
    kind, argv = prepare(sys.argv[1:])
    if kind == "usage":
        print_usage()
        return
    if kind == "error":
        print(argv[0], file=sys.stderr)
        print(file=sys.stderr)
        print_usage()
        sys.exit(2)
    if kind == "help":
        if not argv:
            print_usage()
            return
        if argv[0] == "agents":
            from agents.main import main as agents_main

            agents_main([*argv[1:], "-h"])
            return
        from reconkit import main as recon_main

        recon_main([*argv, "-h"])
        return
    if kind == "agents":
        from agents.main import main as agents_main

        agents_main(argv)
        return
    from reconkit import main as recon_main

    recon_main(argv)


if __name__ == "__main__":
    main()
