"""
reconkit interactive cyber shell (v2.0.1).

Launch:
  python recon_shell.py
  python reconkit.py shell
  python -m shell
"""

from .repl import ReconShell

__all__ = ["ReconShell"]
__version__ = "2.0.1"
