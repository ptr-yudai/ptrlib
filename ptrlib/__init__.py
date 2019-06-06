# coding: utf-8
from ptrlib.util import *
from ptrlib.elf import *
from ptrlib.pwn import *
from ptrlib.crypto import *

from logging import getLogger, Formatter, StreamHandler, INFO, WARNING

class ColoredFormatter(Formatter):
    def format(self, record):
        from ptrlib.console.color import Color

        prefix = ''
        if record.levelno == INFO:
            prefix = '{bold}{green}[+]{end}'.format(bold=Color.BOLD, green=Color.GREEN, end=Color.END)
        elif record.levelno >= WARNING:
            prefix = '{bold}{red}[-]{end}'.format(bold=Color.BOLD, red=Color.RED, end=Color.END)
        else:
            prefix = '{bold}[+]{end}'.format(bold=Color.BOLD, end=Color.END)

        return prefix +  super(ColoredFormatter, self).format(record)

# ptrlib root logger
handler = StreamHandler()
handler.setFormatter(ColoredFormatter("%(funcName)s: %(message)s"))
logger = getLogger(__name__)
logger.setLevel(INFO)
logger.addHandler(handler)
