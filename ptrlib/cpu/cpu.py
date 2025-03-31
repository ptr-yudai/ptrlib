"""This package provides a generic interface for architecture-dependent features.
"""
from ptrlib.annotation import PtrlibArchT, PtrlibBitsT
from .intel.cpu import IntelCPU


def _cpu_factory(arch: PtrlibArchT='intel', bits: PtrlibBitsT=64) -> IntelCPU:
    """Create a CPU instance.

    Examples:
        ```
        x64 = CPU()
        x86 = CPU('intel', 32)
        code = x86.assemble("int3; nop;")
        aarch64 = CPU('arm', 64)
        aarch64.disassemble(b'\x00\x00\x00\x00')
        ```
    """
    if arch == 'intel':
        return IntelCPU(bits)
    if arch == 'arm':
        raise NotImplementedError("This architecture is not supported yet.")
    if arch == 'mips':
        raise NotImplementedError("This architecture is not supported yet.")
    if arch == 'sparc':
        raise NotImplementedError("This architecture is not supported yet.")
    if arch == 'risc-v':
        raise NotImplementedError("This architecture is not supported yet.")

    raise NotImplementedError("Unsupported architecture name.")

CPU = _cpu_factory


__all__ = ['CPU']
