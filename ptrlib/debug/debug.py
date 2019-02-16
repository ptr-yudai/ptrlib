# coding: utf-8
from ptrlib.debug.log import *

log = Log()

def dump(message, level='log'):
    """Print a log message
    
    Print a log message to the console or a file.
    
    Args:
        message (str): The message to dump
        level   (str): The log level (debug, success, error, warning, log)
    """
    global log
    log.dump(message, level)
