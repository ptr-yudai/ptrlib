from ptrlib import logger
from logging import Formatter, DEBUG, INFO, WARNING, ERROR, LogRecord


class Color:
    BLACK     = '\033[30m'
    RED       = '\033[31m'
    GREEN     = '\033[32m'
    YELLOW    = '\033[33m'
    BLUE      = '\033[34m'
    PURPLE    = '\033[35m'
    CYAN      = '\033[36m'
    WHITE     = '\033[37m'
    END       = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'
    INVISIBLE = '\033[08m'
    REVERSE   = '\033[07m'

class ColoredFormatter(Formatter):
    def format(self, record: LogRecord):
        prefix = ''
        postfix = ''
        if INFO <= record.levelno < WARNING:
            prefix = '{bold}{green}[+]{end} {green}'.format(
                bold=Color.BOLD, green=Color.GREEN, end=Color.END
            )
            postfix = Color.END

        elif WARNING <= record.levelno < ERROR:
            prefix = '{bold}{yellow}[WARN]{end} {yellow}'.format(
                bold=Color.BOLD, yellow=Color.YELLOW, end=Color.END
            )
            postfix = Color.END

        elif ERROR <= record.levelno:
            prefix = '{bold}{red}[+]{end} {red}'.format(
                bold=Color.BOLD, red=Color.RED, end=Color.END
            )
            postfix = Color.END

        else:
            prefix = '{bold}[+]{end} '.format(bold=Color.BOLD, end=Color.END)
            postfix = Color.END

        return prefix + \
            super(ColoredFormatter, self).format(record) + \
            postfix
