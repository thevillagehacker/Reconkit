#!/usr/bin/env python3
"""
recon_dashboard.py — Starfleet Bridge console (v3.0.0)

  python recon_dashboard.py
  python recon_dashboard.py --port 8787 --no-browser
  python recon_dashboard.py --host 0.0.0.0          # default (VM / LAN)
  python recon_dashboard.py --host 127.0.0.1        # localhost only

Bridge tabs:
  MISSION      — phase-by-phase fleet replay (play/pause/speed)
  SENSORS      — classic findings table
  PROOF LOCKER — /prove results
  TACTICAL MAP — relation graph
  SCIENCE      — charts

API:
  GET /api/mission?target=example.com
  GET /api/mission/fleet

Default bind is 0.0.0.0 so you can open the UI from a Windows host when
the dashboard runs inside a VM (http://<VM_IP>:8787/).

Do not expose this port to the public internet — it serves recon data
from ~/.reconkit/output.
"""

from dashboard.server import main

if __name__ == "__main__":
    main()
