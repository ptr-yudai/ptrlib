"""Linux syscall registry with architecture selectors.

Usage examples:
- syscall.x64.open
- syscall['arm64'].execve
- syscall.x86['write']

Backed by per-CPU syscall tables in ptrlib.cpu.<arch>.syscall.
"""
from __future__ import annotations

import functools
from typing import Literal

from ptrlib.cpu.intel.syscall import SyscallTable as _IntelSyscallTable
from ptrlib.cpu.arm.syscall import SyscallTable as _ArmSyscallTable
from ptrlib.cpu.mips.syscall import SyscallTable as _MipsSyscallTable


_cache = functools.lru_cache


def _normalize_key(key: str) -> tuple[str, Literal[32, 64]]:
    k = key.lower().replace(' ', '').replace('_', '-').strip()

    # Intel family
    if k in ('x86', 'i386', 'ia32', 'intel32'):  # 32-bit x86
        return ('intel', 32)
    if k in ('x64', 'x86-64', 'amd64', 'intel64'):  # 64-bit x86
        return ('intel', 64)

    # ARM family
    if k in ('arm', 'arm32', 'aarch32'):
        return ('arm', 32)
    if k in ('arm64', 'aarch64', 'aarch'):
        return ('arm', 64)

    # MIPS family
    if k in ('mips', 'mips32'):
        return ('mips', 32)
    if k in ('mips64',):
        return ('mips', 64)

    raise KeyError(f"Invalid architecture key: {key}")


class _LinuxSyscallRegistry:
    """Factory/registry providing syscall tables per architecture.

    Supports both attribute and item access:
        syscall.x64.read  == syscall['x64'].read
    """

    @_cache
    def _table(self, family: str, bits: Literal[32, 64]):
        if family == 'intel':
            return _IntelSyscallTable(bits)
        if family == 'arm':
            return _ArmSyscallTable(bits)
        if family == 'mips':
            return _MipsSyscallTable(bits)
        raise KeyError(f"Unsupported family: {family}")

    def select(self, family: str, bits: Literal[32, 64]):
        """Explicitly select a table by (family, bits)."""
        return self._table(family, bits)

    def __getitem__(self, key: str):
        family, bits = _normalize_key(key)
        return self._table(family, bits)

    def __getattr__(self, key: str):
        # Allow syscall.x64, syscall.arm64, etc.
        try:
            return self[key]
        except KeyError as e:
            raise AttributeError(str(e)) from e


syscall = _LinuxSyscallRegistry()

__all__ = ['syscall']

