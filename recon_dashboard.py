#!/usr/bin/env python3
"""
recon_dashboard.py — local findings dashboard (v3.0.0)

  python recon_dashboard.py
  python recon_dashboard.py --port 8787 --no-browser
  python recon_dashboard.py --host 127.0.0.1          # default (localhost)
  python recon_dashboard.py --host 0.0.0.0            # VM / LAN

Tabs:
  SCAN      — live module tracker (play/pause from the UI)
  FINDINGS  — recon records (default C1+)
  PROOFS    — /prove results
  GRAPH     — relationship graph
  INSIGHTS  — charts

API:
  GET  /api/scan?target=example.com
  POST /api/run?target=example.com&modules=quick
  POST /api/control?action=pause|resume|stop

Do not expose this port to the public internet — it serves recon data
from ~/.reconkit/output.
"""

from dashboard.server import main

if __name__ == "__main__":
    main()
