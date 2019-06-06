from logging import getLogger
from ptrlib.util.encoding import str2bytes

logger = getLogger(__name__)

def p16(data, order='little'):
    if not isinstance(data, int):
        logger.warn("p16: {} given ('int' expected)".format(type(data)))
    return data.to_bytes(2, byteorder=order)

def p32(data, order='little'):
    if not isinstance(data, int):
        logger.warn("p32: {} given ('int' expected)".format(type(data)))
    return data.to_bytes(4, byteorder=order)

def p64(data, order='little'):
    if not isinstance(data, int):
        logger.warn("p64: {} given ('int' expected)".format(type(data)))
    return data.to_bytes(8, byteorder=order)

def u16(data, order='little', signed=False):
    if isinstance(data, str):
        data = str2bytes(data)
    if not isinstance(data, bytes):
        logger.warn("u16: {} given ('bytes' expected)".format(type(data)))
    return int.from_bytes(data, byteorder=order, signed=signed)

def u32(data, order='little', signed=False):
    if isinstance(data, str):
        data = str2bytes(data)
    if not isinstance(data, bytes):
        logger.warn("u32: {} given ('bytes' expected)".format(type(data)))
    return int.from_bytes(data, byteorder=order, signed=signed)

def u64(data, order='little', signed=False):
    if isinstance(data, str):
        data = str2bytes(data)
    if not isinstance(data, bytes):
        logger.warn("u64: {} given ('bytes' expected)".format(type(data)))
    return int.from_bytes(data, byteorder=order, signed=signed)
