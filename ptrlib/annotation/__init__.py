"""This package provides types defined in ptrlib
"""
from typing import Literal

PtrlibArchT = Literal['unknown', 'intel', 'arm', 'risc-v', 'sparc', 'mips']
PtrlibBitsT = Literal[16, 32, 64]
PtrlibEndiannessT = Literal['little', 'big']
PtrlibAssemblySyntaxT = Literal['intel', 'att']
PtrlibAssemblerT = Literal['keystone', 'gcc', 'nasm', 'none']
PtrlibDisassemblerT = Literal['capstone', 'objdump', 'none']

__all__ = ['PtrlibArchT', 'PtrlibBitsT', 'PtrlibEndiannessT',
           'PtrlibAssemblySyntaxT', 'PtrlibAssemblerT', 'PtrlibDisassemblerT']
