from ptrlib.debug.debug import *

def bytes2str(data):
    """Convert bytes to str
    """
    if isinstance(data, bytes):
        return ''.join(list(map(chr, data)))
    else:
        dump("bytes2str: {} given ('bytes' expected)".format(type(data)), "warning")

def str2bytes(data):
    """Convert str to bytes
    """
    if isinstance(data, str):
        return bytes(list(map(ord, data)))
    else:
        dump("str2bytes: {} given ('str' expected)".format(type(data)), "warning")
