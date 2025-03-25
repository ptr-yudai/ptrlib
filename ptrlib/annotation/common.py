"""This package defines types commonly used in ptrlib.
"""
from typing import Literal

PtrlibArchT = Literal['intel', 'arm', 'risc-v', 'sparc', 'mips']
PtrlibBitsT = Literal[32, 64]
PtrlibEndiannessT = Literal['little', 'big']


__all__ = ['PtrlibArchT', 'PtrlibBitsT', 'PtrlibEndiannessT']
