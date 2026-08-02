"""
Optional plugin hooks (Tier D).

Drop a module in plugins/ that defines:
  COMMANDS = [{"name": "...", "usage": "...", "summary": "...", "handler": callable}]

Shell loads these at startup if present. Core works without any plugins.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Any

_PLUGIN_DIR = Path(__file__).resolve().parent


def load_plugin_commands() -> list[dict[str, Any]]:
    cmds: list[dict[str, Any]] = []
    if not _PLUGIN_DIR.is_dir():
        return cmds
    for mod in pkgutil.iter_modules([str(_PLUGIN_DIR)]):
        if mod.name.startswith("_"):
            continue
        try:
            m = importlib.import_module(f"plugins.{mod.name}")
        except Exception:
            continue
        for c in getattr(m, "COMMANDS", []) or []:
            if isinstance(c, dict) and c.get("name") and c.get("handler"):
                cmds.append(c)
    return cmds
