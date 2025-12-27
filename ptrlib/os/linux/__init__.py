"""Linux-specific OS helpers.

Exports:
- signal_name: Convert signal number to string (optionally with details)
- syscall: Linux syscall registry with arch selectors (x86, x64, arm, aarch64)
- consts: Linux constant tables (static, by category)
"""

from .signal import signal_name
from .syscall import syscall
from . import consts

__all__ = ['signal_name', 'syscall', 'consts']
