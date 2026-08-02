#!/usr/bin/env python3
"""
recon_prove.py — Safe validation layer for reconkit v3.0.0

Build a queue from the findings index and run non-destructive validators
(XSS marker reflect, SSTI math canary, nuclei artifact recheck, takeover
fingerprint, SSRF review). No sqlmap / shells / dumps.

  python recon_prove.py policy
  python recon_prove.py techniques
  python recon_prove.py queue --target example.com
  python recon_prove.py run --target example.com
  python recon_prove.py run --target example.com --technique xss_reflect
  python recon_prove.py list --target example.com
  python recon_prove.py show --target example.com --id <proof_id>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _scope_check(target: str) -> bool:
    try:
        import reconkit as rk

        return rk.in_scope(target)
    except Exception:
        return False


def cmd_policy(_args: argparse.Namespace) -> None:
    from prove.policy import load_policy, policy_summary

    print(policy_summary())
    if _args.json:
        print(json.dumps(load_policy(), indent=2))


def cmd_techniques(_args: argparse.Namespace) -> None:
    from prove.validators import list_techniques

    print("Safe validators:")
    for t in list_techniques():
        print(f"  • {t}")


def cmd_queue(args: argparse.Namespace) -> None:
    from prove.queue import build_queue, queue_summary

    items = build_queue(
        target=args.target or None,
        notable_only=not args.all,
        limit=args.limit,
        techniques=[args.technique] if args.technique else None,
        include_unmapped=args.include_manual,
    )
    if args.json:
        slim = [{k: v for k, v in it.items() if k != "finding"} for it in items]
        print(json.dumps(slim, indent=2))
    else:
        print(queue_summary(items))
        if not items:
            print("\nTip: run recon + `python reconkit.py findings reindex` first.")


def cmd_run(args: argparse.Namespace) -> None:
    import reconkit as rk
    from prove.policy import load_policy
    from prove.queue import build_queue
    from prove.runner import run_proofs, summarize_results

    target = (args.target or "").strip()
    if not target:
        print("error: --target required", file=sys.stderr)
        sys.exit(2)
    rk.require_scope_or_exit(target)

    pol = load_policy()
    print(pol.get("banner") or "SAFE VALIDATION ONLY")
    print()

    items = build_queue(
        target=target,
        notable_only=not args.all,
        limit=args.limit,
        techniques=[args.technique] if args.technique else None,
        include_unmapped=False,
    )
    if args.dry_run:
        from prove.queue import queue_summary

        print("DRY RUN — would validate:")
        print(queue_summary(items))
        return

    if not items:
        print("Nothing to prove (empty queue). Reindex findings or widen with --all.")
        sys.exit(0)

    def progress(i: int, total: int, p: dict) -> None:
        print(f"  [{i}/{total}] {p.get('status')}: {p.get('technique')} {(p.get('asset') or '')[:60]}")

    results = run_proofs(items, policy=pol, scope_check=_scope_check, on_progress=progress)
    print()
    print(summarize_results(results))
    print(f"\nSaved under ~/.reconkit/output/{target}/proofs/")


def cmd_list(args: argparse.Namespace) -> None:
    from prove.store import list_all_proof_targets, load_proofs

    target = (args.target or "").strip()
    if not target:
        targets = list_all_proof_targets()
        print("Targets with proofs:", ", ".join(targets) or "(none)")
        return
    proofs = load_proofs(target)
    if args.json:
        print(json.dumps(proofs, indent=2))
        return
    print(f"{len(proofs)} proof(s) for {target}")
    for p in proofs[:50]:
        print(
            f"  {p.get('id')}  [{p.get('status')}]  {p.get('technique')}  "
            f"{(p.get('title') or '')[:40]}"
        )


def cmd_show(args: argparse.Namespace) -> None:
    from prove.store import load_proofs

    target = (args.target or "").strip()
    pid = (args.id or "").strip()
    if not target or not pid:
        print("error: --target and --id required", file=sys.stderr)
        sys.exit(2)
    for p in load_proofs(target):
        if p.get("id") == pid or (p.get("id") or "").startswith(pid):
            print(json.dumps(p, indent=2))
            return
    print(f"proof not found: {pid}", file=sys.stderr)
    sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon_prove",
        description="Safe validation (prove) layer for reconkit — no destructive exploits",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pol = sub.add_parser("policy", help="Show exploit/prove policy")
    pol.add_argument("--json", action="store_true")
    pol.set_defaults(func=cmd_policy)

    tech = sub.add_parser("techniques", help="List safe validators")
    tech.set_defaults(func=cmd_techniques)

    q = sub.add_parser("queue", help="Build queue from findings index")
    q.add_argument("--target", default="")
    q.add_argument("--limit", type=int, default=None)
    q.add_argument("--technique", default="")
    q.add_argument("--all", action="store_true", help="Include non-notable findings")
    q.add_argument("--include-manual", action="store_true")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_queue)

    r = sub.add_parser("run", help="Run safe validators for a target")
    r.add_argument("--target", required=True)
    r.add_argument("--limit", type=int, default=None)
    r.add_argument("--technique", default="")
    r.add_argument("--all", action="store_true")
    r.add_argument("--dry-run", action="store_true")
    r.set_defaults(func=cmd_run)

    ls = sub.add_parser("list", help="List saved proofs")
    ls.add_argument("--target", default="")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(func=cmd_list)

    sh = sub.add_parser("show", help="Show one proof JSON")
    sh.add_argument("--target", required=True)
    sh.add_argument("--id", required=True)
    sh.set_defaults(func=cmd_show)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
