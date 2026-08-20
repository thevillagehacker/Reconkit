#!/usr/bin/env python3
"""
recon_shell.py — interactive prompt for reconkit v3.0.0

Usage:
  python recon_shell.py
  python recon_shell.py --target example.com -v 2
  python recon_shell.py --debug          # verbose=2
  python recon_shell.py -v 3            # live tool streams

Inside the shell:
  type /       LIVE autocomplete dropdown (commands + subcommands)
               requires: pip install prompt_toolkit
  / + Enter    full interactive slash menu (pick by number)
  /help        full usage catalog
  /scan        interactive module picker
  /run …       direct pipeline
  /agent …     multi-agent LLM recon
  /verbose 3   stream live scan tool output
"""

from shell.repl import main

if __name__ == "__main__":
    main()
