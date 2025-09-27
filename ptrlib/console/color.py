from logging import Formatter, INFO, WARNING, ERROR, LogRecord

__all__ = ['Color', 'ColoredFormatter']


class Color:
    BLACK     = '\033[30m'
    RED       = '\033[31m'
    GREEN     = '\033[32m'
    YELLOW    = '\033[33m'
    BLUE      = '\033[34m'
    PURPLE    = '\033[35m'
    CYAN      = '\033[36m'
    WHITE     = '\033[37m'
    BRIGHT_RED     = '\033[91m'
    BRIGHT_GREEN   = '\033[92m'
    BRIGHT_YELLOW  = '\033[93m'
    BRIGHT_BLUE    = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN    = '\033[96m'
    BRIGHT_WHITE   = '\033[97m'
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
            prefix = f'{Color.BOLD}{Color.GREEN}[+]{Color.END} {Color.GREEN}'
            postfix = Color.END

        elif WARNING <= record.levelno < ERROR:
            prefix = f'{Color.BOLD}{Color.YELLOW}[WARN]{Color.END} {Color.YELLOW}'
            postfix = Color.END

        elif ERROR <= record.levelno:
            prefix = f'{Color.BOLD}{Color.RED}[+]{Color.END} {Color.RED}'
            postfix = Color.END

        else:
            prefix = f'{Color.BOLD}[+]{Color.END} '
            postfix = Color.END

        return prefix + super(ColoredFormatter, self).format(record) + postfix