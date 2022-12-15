import struct
from ptrlib.binary.encoding.byteconv import str2bytes


def u8(data, signed=False):
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError("u8: {} given ('bytes' expected)".format(type(data)))

    return int.from_bytes(data, 'big', signed=signed)

def u16(data, byteorder='little', signed=False):
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError("u16: {} given ('bytes' expected)".format(type(data)))

    return int.from_bytes(data, byteorder=byteorder, signed=signed)

def u32(data, byteorder='little', signed=False, type=int):
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError("u32: {} given ('bytes' expected)".format(type(data)))

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
        raise ValueError("u64: {} given ('bytes' expected)".format(type(data)))

    if type == float:
        return struct.unpack(
            '{}d'.format('<' if byteorder == 'little' else '>'),
            data
        )[0]

    return int.from_bytes(data, byteorder=byteorder, signed=signed)
