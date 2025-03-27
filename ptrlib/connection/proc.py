"""This package provides Process class
"""
import os
from .unixproc import UnixProcess
from .winproc import WinProcess

if os.name == 'nt':
    Process = WinProcess
else:
    Process = UnixProcess

__all__ = ['Process']
