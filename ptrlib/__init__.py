# coding: utf-8
from ptrlib.util import *
from ptrlib.elf import *
from ptrlib.pwn import *
from ptrlib.crypto import *
from ptrlib.console import *
from logging import getLogger, Formatter, StreamHandler, INFO, WARNING, ERROR

class ColoredFormatter(Formatter):
    def format(self, record):
        prefix = ''
        if record.levelno == INFO:
            prefix = '{bold}{green}[+]{end} '.format(bold=Color.BOLD, green=Color.GREEN, end=Color.END)
        if record.levelno == WARNING:
            prefix = '{bold}{red}[+]{end} '.format(bold=Color.BOLD, red=Color.RED, end=Color.END)
        elif record.levelno >= ERROR:
            prefix = '{bold}{yellow}[WARN]{end} '.format(bold=Color.BOLD, yellow=Color.YELLOW, end=Color.END)
        else:
            prefix = '{bold}[+]{end} '.format(bold=Color.BOLD, end=Color.END)

        return prefix +  super(ColoredFormatter, self).format(record)

class DeprecatedLog(object):
    def __init__(self):
        self.warn = False
    
    def dump(self, msg, level=''):
        if not self.warn:
            logger.warning("`log.dump` is no longer available! Use `logger` instead")
        self.warn = True

# ptrlib root logger
handler = StreamHandler()
handler.setFormatter(ColoredFormatter("%(funcName)s: %(message)s"))
logger = getLogger(__name__)
logger.setLevel(INFO)
logger.addHandler(handler)

# For compatibility
log = DeprecatedLog()
dump = log.dump
