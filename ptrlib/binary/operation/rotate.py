from logging import getLogger

logger = getLogger(__name__)


def rol(data, n, bits=32):
    """Rotate left
    """
    if isinstance(data, int):
        if data.bit_length() > bits:
            logger.warning("data of bits={} given (bits={} expected)".format(data.bit_length(), bits))
            data &= ((1 << bits) - 1)
        return ((data << n) | (data >> (bits - n))) & ((1 << bits) - 1)

    elif isinstance(data, str) \
         or isinstance(data, bytes) \
         or isinstance(data, list):
        return data[n:] + data[:n]

    else:
        raise ValueError("{} given ('int'/'str'/'bytes'/'list' expected)".format(type(data)))

def ror(data, n, bits=32):
    """Rotate right
    """
    if isinstance(data, int):
        if data.bit_length() > bits:
            logger.warning("data of bits={} given (bits={} expected)".format(data.bit_length(), bits))
            data &= ((1 << bits) - 1)
        return ((data >> n) | ((data & ((1 << n) - 1)) << (bits - n))) & ((1 << bits) - 1)

    elif isinstance(data, str) \
         or isinstance(data, bytes) \
         or isinstance(data, list):
        return data[-n:] + data[:-n]

    else:
        raise ValueError("{} given ('int'/'str'/'bytes'/'list' expected)".format(type(data)))
