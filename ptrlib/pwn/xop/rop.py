"""This package provides some utilities for ROP (return oriented programming).
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Union
from ptrlib.binary.encoding import bytes2str
from ptrlib.types import PtrlibAssemblySyntaxT, GeneratorOrInt

if TYPE_CHECKING:
    from ptrlib.filestruct import ELF, PE


class GadgetFinder:
    """Search gadgets
    """
    def __init__(self, binary: Union[ELF, PE]):
        """
        Args:
            binary (Union[ELF,PE]): An ELF or PE instance.
        """
        self._bin = binary

    def search(self, code: str, syntax: PtrlibAssemblySyntaxT='intel'):
        """Find ROP/COP gadgets.

        Args:
            code (str): Assembly or machine code of ROP gadget
            syntax (str): Syntax of code (default to intel)

        Returns:
            generator: Generator to yield the addresses of the found gadgets
        """
        if isinstance(code, bytes):
            code = bytes2str(code)

        # Assemble gadget
        bytecode = self._bin.cpu.assemble(code, syntax=syntax)
        return GeneratorOrInt(self._bin.search(bytecode, executable=True).generator, code.encode())


__all__ = ['GadgetFinder']
