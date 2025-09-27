"""This package provides every feature of ptrlib
"""
from logging import getLogger, INFO, StreamHandler
from .algorithm import *
from .types import *
from .binary import *
from .connection import *
from .console import *
from .cpu import *
from .crypto import *
from .filestruct import *
from .pwn import *

# ptrlib root logger
_handler = StreamHandler()
_handler.setFormatter(ColoredFormatter("%(funcName)s: %(message)s"))
logger = getLogger(__name__)
logger.setLevel(INFO)
logger.addHandler(_handler)
