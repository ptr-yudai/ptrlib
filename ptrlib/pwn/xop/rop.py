"""This package provides some utilities for ROP (return oriented programming).
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Generator, Union
from ptrlib.annotation import PtrlibAssemblySyntaxT
from ptrlib.binary.encoding import bytes2str

if TYPE_CHECKING:
    from ptrlib.filestruct import ELF, PE


class Gadget:
    """A class representing a gadget.
    """
    def __init__(self, generator: Generator[int, None, None], code: str):
        self._generator = generator
        self._code = code
        self._first = None

    def __int__(self) -> int:
        if self._first is None:
            v = next(self._generator)
            self._first = v
            return v
        return self._first

    def __iter__(self) -> 'Gadget':
        return self

    def __next__(self) -> int:
        v = next(self._generator)
        if self._first is None:
            self._first = v
        return v

    def __str__(self) -> str:
        return f'ROPGadget({repr(self._code)})'


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
        return Gadget(self._bin.search(bytecode, executable=True), code)


__all__ = ['GadgetFinder', 'Gadget']
