from .algorithm import *
from .arch import *
from .binary import *
from .connection import *
from .console import *
from .crypto import *
from .filestruct import *
from .pwn import *
from logging import getLogger, INFO, StreamHandler

# ptrlib root logger
_handler = StreamHandler()
_handler.setFormatter(ColoredFormatter("%(funcName)s: %(message)s"))
logger = getLogger(__name__)
logger.setLevel(INFO)
logger.addHandler(_handler)