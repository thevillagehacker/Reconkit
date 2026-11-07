# Reconkit

Reconnaissance engine for authorized bug bounty and penetration tests.
Detection and safe validation only. The CLI is the engine. Findings, proofs,
and the attack graph are shell commands.

```bash
python recon.py example.com
python recon.py example.com --modules dns,httpprobe
python recon.py example.com --review
python recon.py shell
```

The target must already be in `~/.reconkit/scope.txt`.

Output lands in `~/.reconkit/output/<target>/`. Each tool writes
`tools/<stage>/<tool>.txt` as soon as it finishes. `--review` (or
`RECON_SUPERVISOR=1`) adds a model note per phase in `reviews/<phase>.txt`
and `reviews/summary.txt` when the run finishes. A normal run does not call
a model. `/stop` skips the summary.

Command catalog: [USAGE.md](USAGE.md), [HUNTER.md](HUNTER.md).
