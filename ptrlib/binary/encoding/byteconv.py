from logging import getLogger

logger = getLogger(__name__)


def bytes2str(data):
    """Convert bytes to str
    """
    if isinstance(data, bytes):
        return ''.join(list(map(chr, data)))
    else:
        logger.warning("{} given ('bytes' expected)".format(type(data)))

def str2bytes(data):
    """Convert str to bytes
    """
    if isinstance(data, str):
        return bytes(list(map(ord, data)))
    else:
        raise ValueError("{} given ('str' expected)".format(type(data)))
