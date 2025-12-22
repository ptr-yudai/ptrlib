"""Linux-specific OS helpers.

Exports:
- signal_name: Convert signal number to string (optionally with details)
- syscall: Linux syscall registry with arch selectors (x86, x64, arm, aarch64)
- consts: Experimental constant resolver via system headers
"""

from .signal import signal_name
from .syscall import syscall
from .consts import consts

__all__ = ['signal_name', 'syscall', 'consts']

