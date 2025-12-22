"""Operating system helpers and registries.

This package consolidates OS-dependent utilities that used to live under
``ptrlib.arch``. Architecture-dependent components (assemblers, instruction sets,
CPU models) are under ``ptrlib.cpu``; OS-dependent components (signals, syscalls,
path lookups) are under ``ptrlib.os``.

Public API:
- which(): Cross-platform executable resolver.
- linux: Linux-specific helpers (e.g., syscall registry, signal names).
"""

from .path import which

__all__ = [
    'which',
]

