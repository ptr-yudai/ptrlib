from logging import getLogger
from typing import List, Mapping
from ptrlib.binary.encoding import str2bytes
from .tube import Tube
import ctypes
import os
import time

_is_windows = os.name == 'nt'
if _is_windows:
    import win32api
    import win32con
    import win32file
    import win32pipe
    import win32process
    import win32security

logger = getLogger(__name__)
