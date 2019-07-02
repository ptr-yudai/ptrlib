from logging import getLogger

logger = getLogger(__name__)

def xor(data, key):
    assert isinstance(data, str) or isinstance(data, bytes)
    assert isinstance(key, str) or isinstance(key, bytes)

    result = b''
    for i in range(len(data)):
        d = ord(data[i]) if isinstance(data, str) else data[i]
        k = ord(key[i % len(key)]) if isinstance(key, str) else key[i % len(key)]
        result += bytes([d ^ k])

    return result

def rol(data, n, bits=32):
    """Rotate left
    """
    if isinstance(data, int):
        if data.bit_length() > bits:
            logger.error("data of bits={} given (bits={} expected)".format(data.bit_length(), bits))
            data &= ((1 << bits) - 1)
        return ((data << n) | (data >> (bits - n))) & ((1 << bits) - 1)
    elif isinstance(data, str) or isinstance(data, bytes):
        return data[n:] + data[:n]
    else:
        logger.warn("{} given ('int'/'str'/'bytes' expected)".format(type(data)))

def ror(data, n, bits=32):
    """Rotate right
    """
    if isinstance(data, int):
        if data.bit_length() > bits:
            logger.error("data of bits={} given (bits={} expected)".format(data.bit_length(), bits))
            data &= ((1 << bits) - 1)
        return ((data >> n) | ((data & ((1 << n) - 1)) << (bits - n))) & ((1 << bits) - 1)
    elif isinstance(data, str) or isinstance(data, bytes):
        return data[-n:] + data[:-n]
    else:
        logger.warn("{} given ('int'/'str'/'bytes' expected)".format(type(data)))
