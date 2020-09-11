import struct
from logging import getLogger
from ptrlib.util.encoding import str2bytes

logger = getLogger(__name__)

def p16(data, byteorder='little', signed=False):
    if not isinstance(data, int):
        logger.warn("p16: {} given ('int' expected)".format(type(data)))
    if data < 0:
        signed = True

    return data.to_bytes(2, byteorder=byteorder, signed=signed)

def p32(data, byteorder='little', signed=False):
    if isinstance(data, float):
        return struct.pack(
            '{}f'.format('<' if byteorder == 'little' else '>'),
            data
        )

    if not isinstance(data, int):
        logger.warn("p32: {} given ('int'/'float' expected)".format(type(data)))
    if data < 0:
        signed = True

    return data.to_bytes(4, byteorder=byteorder, signed=signed)

def p64(data, byteorder='little', signed=False):
    if isinstance(data, float):
        return struct.pack(
            '{}d'.format('<' if byteorder == 'little' else '>'),
            data
        )

    if not isinstance(data, int):
        logger.warn("p64: {} given ('int'/'float' expected)".format(type(data)))
    if data < 0:
        signed = True

    return data.to_bytes(8, byteorder=byteorder, signed=signed)

def u16(data, byteorder='little', signed=False):
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        logger.warn("u16: {} given ('bytes' expected)".format(type(data)))

    return int.from_bytes(data, byteorder=byteorder, signed=signed)

def u32(data, byteorder='little', signed=False, type=int):
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        logger.warn("u32: {} given ('bytes' expected)".format(type(data)))

    if type == float:
        return struct.unpack(
            '{}f'.format('<' if byteorder == 'little' else '>'),
            data
        )[0]

    return int.from_bytes(data, byteorder=byteorder, signed=signed)

def u64(data, byteorder='little', signed=False, type=int):
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        logger.warn("u64: {} given ('bytes' expected)".format(type(data)))

    if type == float:
        return struct.unpack(
            '{}d'.format('<' if byteorder == 'little' else '>'),
            data
        )[0]

    return int.from_bytes(data, byteorder=byteorder, signed=signed)
