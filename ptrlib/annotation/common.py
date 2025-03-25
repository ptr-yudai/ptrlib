"""This package defines types commonly used in ptrlib.
"""
from typing import Literal

PtrlibArch = Literal['x86', 'x64', 'arm', 'aarch64']


__all__ = ['PtrlibArch']
