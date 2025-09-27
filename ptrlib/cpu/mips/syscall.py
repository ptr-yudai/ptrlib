"""System call table for MIPS architectures.
"""
import functools
from ptrlib.types import PtrlibBitsT

cache = functools.lru_cache


class SyscallTable:
    """Sytem call table for MIPS architectures.
    """
    def __init__(self, bits: PtrlibBitsT):
        self._bits = bits

    @cache
    def __getitem__(self, name: str) -> int:
        raise NotImplementedError("Syscall table is not implemented for MIPS architecture.")

    def __getattr__(self, name: str) -> int:
        return self[name]


__all__ = ['SyscallTable']
