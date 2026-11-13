# Reconkit

Reconnaissance engine for authorized bug bounty and penetration tests.
Detection and safe validation only. The CLI is the engine. Findings and
proofs are `recon.py` commands.

```bash
python recon.py example.com
python recon.py example.com --modules dns,httpprobe
python recon.py example.com --review
python recon.py playbook list
```

The target must already be in `~/.reconkit/scope.txt`.

Output lands in `~/.reconkit/output/<target>/`. Each result is written once.
Per-source subdomain and crawl lists go to `tools/<stage>/<tool>.txt` as that
tool finishes. Other stage results are one file at the output root, with the
exit code in `tools/<stage>/<tool>.txt.rc`. `--review` (or
`RECON_SUPERVISOR=1`) adds a model note per phase in `reviews/<phase>.txt`
and `reviews/summary.txt` when the run finishes. A normal run does not call
a model. Ctrl+C skips the summary.

A scan prints one phase line, one row when a tool finishes, one line per
probed host, and `[+] SCAN COMPLETE`.

`python recon.py agents <target>` asks the model for the next one to three
modules, then runs those stages. It keeps walking the pipeline until nothing
runnable remains, the remaining modules are blocked for lack of hosts or URLs,
or the step cap is reached. The module order, `skip_if_chosen`, and the
dry-run rules are in [USAGE.md](USAGE.md) section 10.

Command catalog: [USAGE.md](USAGE.md), [HUNTER.md](HUNTER.md).
