"""This package provides some utilities for ROP (return oriented programming).
"""
from __future__ import annotations
from typing import TYPE_CHECKING
from ptrlib.cpu import ArmCPU, IntelCPU
from ptrlib.types import PtrlibAssemblySyntaxT, GeneratorOrInt

if TYPE_CHECKING:
    from ptrlib.filestruct import ELF, PE


class GadgetFinder:
    """Search gadgets
    """
    def __init__(self, binary: ELF | PE):
        """
        Args:
            binary (Union[ELF,PE]): An ELF or PE instance.
        """
        self._bin = binary

    def search(self,
               code: str | bytes,
               syntax: PtrlibAssemblySyntaxT='intel',
               thumb: bool=False) -> GeneratorOrInt:
        """Find ROP/COP gadgets.

        Args:
            code (str/bytes): Assembly or machine code of ROP gadget.
            syntax (str): Syntax of code. Used only for Intel architecture.
            thumb (bool): Thumb mode. Used only for ARM architecture.

        Returns:
            generator: Generator to yield the addresses of the found gadgets
        """
        if isinstance(code, (bytes, bytearray, memoryview)):
            return self._bin.search(code, executable=True)

        # Assemble gadget
        if isinstance(self._bin.cpu, IntelCPU):
            bytecode = self._bin.cpu.assemble(code, syntax=syntax)
        elif isinstance(self._bin.cpu, ArmCPU):
            bytecode = self._bin.cpu.assemble(code, thumb=thumb)
        else:
            bytecode = self._bin.cpu.assemble(code)

        return self._bin.search(bytecode, executable=True)


__all__ = ['GadgetFinder']
