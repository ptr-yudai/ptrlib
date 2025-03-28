"""This package defines types commonly used in ptrlib.
"""
from typing import Literal

PtrlibArchT = Literal['unknown', 'intel', 'arm', 'risc-v', 'sparc', 'mips']
PtrlibBitsT = Literal[32, 64]
PtrlibEndiannessT = Literal['little', 'big']
PtrlibAssemblySyntaxT = Literal['intel', 'att']

__all__ = ['PtrlibArchT', 'PtrlibBitsT', 'PtrlibEndiannessT', 'PtrlibAssemblySyntaxT']
