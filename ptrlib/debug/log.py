# coding: utf-8
from ptrlib.debug.color import *
import sys

class Log(object):
    def __init__(self, filepath=None, level='debug'):
        self.level = level
        if filepath:
            self.f = open(filepath, 'w')
        else:
            self.f = sys.stderr

    def dump(self, message, level='log'):
        """Print a log message
        
        Print a log message to the console or a file.

        Args:
            message (str): The message to dump
            level   (str): The log level (debug, success, error, warning, log)
        """
        if level == 'debug':
            # DEBUG
            self.f.write(
                "{bold}{cyan}[DEBUG]{end} {0}\n".format(
                    message, bold=Color.BOLD, cyan=Color.CYAN, end=Color.END
                )
            )
        elif level == 'success':
            # SUCCESS
            self.f.write(
                "{bold}{green}[+]{end} {0}\n".format(
                    message, bold=Color.BOLD, green=Color.GREEN, end=Color.END
                )
            )
        elif level == 'error':
            # ERROR
            self.f.write(
                "{bold}{yellow}[-]{end} {0}\n".format(
                    message, bold=Color.BOLD, yellow=Color.YELLOW, end=Color.END
                )
            )
        elif level == 'warning':
            # WARN
            self.f.write(
                "{bold}{red}[WARN]{end} {0}\n".format(
                    message, bold=Color.BOLD, red=Color.RED, end=Color.END
                )
            )
        else:
            # LOG
            self.f.write(
                "{bold}[ptrlib]{end} {0}\n".format(
                    message, bold=Color.BOLD, end=Color.END
                )
            )
        self.f.flush()

    def __def__(self):
        self.f.close()
