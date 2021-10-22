from logging import getLogger

logger = getLogger(__name__)

def bytes2str(data):
    """Convert bytes to str
    """
    if isinstance(data, bytes):
        return ''.join(list(map(chr, data)))
    else:
        logger.warn("{} given ('bytes' expected)".format(type(data)))

def str2bytes(data):
    """Convert str to bytes
    """
    if isinstance(data, str):
        return bytes(list(map(ord, data)))
    else:
        logger.warn("{} given ('str' expected)".format(type(data)))

def has_space(data, warn=False):
    """Check if payload has "space" of C locale
    """
    if isinstance(data, str):
        data = str2bytes(data)

    # SPC, TAB, LF, VT, FF, CR
    whitespace = [0x20, 0x09, 0x0a, 0x0b, 0x0c, 0x0d]
    for i, c in enumerate(data):
        if c in whitespace:
            if warn:
                logger.error("Whitespace '\\x{:02x}' at offset 0x{:x}".format(c, i))
            return True

    return False

""" Check if payload is safe for an input function """
def is_scanf_safe(data, warn=False): # scanf
    return not has_space(data, warn)

def is_stream_safe(data, warn=False): # stream
    return not has_space(data, warn)

def is_cin_safe(data, warn=False): # cin
    return not has_space(data, warn)

def is_fgets_safe(data, warn=False): # fgets
    if isinstance(data, str):
        data = str2bytes(data)

    if b'\n' not in data:
        return True

    if warn:
        logger.error("Newline '\\x0a' at offset 0x{:x}".format(
            data.index(b'\n')
        ))
    return False

def is_gets_safe(data):    # gets
    return is_fgets_safe(data)

def is_getline_safe(data): # getline
    return is_fgets_safe(data)
