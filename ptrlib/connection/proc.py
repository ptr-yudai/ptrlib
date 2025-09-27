"""This package provides Process class
"""
import os

if os.name == 'nt':
    from .winproc import WinProcess
    Process = WinProcess
else:
    from .unixproc import UnixProcess
    Process = UnixProcess

__all__ = ['Process']
