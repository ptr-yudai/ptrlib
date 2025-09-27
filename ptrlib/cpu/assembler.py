"""Alias for some assembler functions
"""
from ptrlib.types import PtrlibBitsT
from .cpu import IntelCPU

def nasm(code: str, bits: PtrlibBitsT=64, org: int=0):
    """Assemble x86/x86-64 code with NASM

    Args:
      code (str): Assembly code
      bits (int): Architecture bits (Default is 64)
      org (int): Specify address (ORG instruction)

    Returns:
      bytes: Machine code
    """
    cpu = IntelCPU(bits)
    cpu.assembler = 'nasm'
    return cpu.assemble(code, address=org)

__all__ = ['nasm']
