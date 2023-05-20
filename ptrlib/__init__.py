from .algorithm import *
from .arch import *
from .binary import *
from .connection import *
from .console import *
from .crypto import *
from .filestruct import *
from .pwn import *
from logging import getLogger, StreamHandler

# ptrlib root logger
handler = StreamHandler()
handler.setFormatter(ColoredFormatter("%(funcName)s: %(message)s"))
logger = getLogger(__name__)
logger.setLevel(INFO)
logger.addHandler(handler)

