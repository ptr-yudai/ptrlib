"""This package provides a generic interface for architecture-dependent features.
"""
from typing import overload, Literal
from ptrlib.types import PtrlibArchT, PtrlibBitsT
from .intel.cpu import IntelCPU
from .arm.cpu import ArmCPU
from .mips.cpu import MipsCPU

PtrlibCpuT = IntelCPU | ArmCPU | MipsCPU

# --- overloads start ---
@overload
def _cpu_factory() -> IntelCPU: ...
@overload
def _cpu_factory(arch: Literal['intel'], bits: PtrlibBitsT = ...) -> IntelCPU: ...
@overload
def _cpu_factory(arch: Literal['arm'], bits: PtrlibBitsT = ...) -> ArmCPU: ...
@overload
def _cpu_factory(arch: Literal['mips'], bits: PtrlibBitsT = ...) -> MipsCPU: ...
@overload
def _cpu_factory(arch: PtrlibArchT, bits: PtrlibBitsT = ...) -> PtrlibCpuT: ...
# --- overloads end ---

def _cpu_factory(arch: PtrlibArchT='intel',
                 bits: PtrlibBitsT=64) -> PtrlibCpuT:
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
        return ArmCPU(bits)
    if arch == 'mips':
        return MipsCPU(bits)
    if arch == 'sparc':
        raise NotImplementedError("This architecture is not supported yet.")
    if arch == 'risc-v':
        raise NotImplementedError("This architecture is not supported yet.")

    raise NotImplementedError("Unsupported architecture name.")

CPU = _cpu_factory


__all__ = ['CPU', 'ArmCPU', 'IntelCPU', 'PtrlibCpuT']
