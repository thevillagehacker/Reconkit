"""
reconkit interactive shell (v3.0.0).

Launch:
  python recon_shell.py
  python reconkit.py shell
  python -m shell
"""

from .repl import ReconShell

__all__ = ["ReconShell"]
__version__ = "3.0.0"
