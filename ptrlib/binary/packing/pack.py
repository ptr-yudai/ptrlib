import struct
from typing import Union
try:
    from typing import Literal
except:
    from typing_extensions import Literal


def p8(data: int) -> bytes:
    if not isinstance(data, int):
        raise ValueError("p8: {} given ('int' expected)".format(type(data)))

    return (data & 0xff).to_bytes(1, byteorder='little')

def p16(data: int, byteorder: Literal["little", "big"]='little') -> bytes:
    if not isinstance(data, int):
        raise ValueError("p16: {} given ('int' expected)".format(type(data)))

    return (data & 0xffff).to_bytes(2, byteorder=byteorder)

def p32(data: Union[int, float], byteorder: Literal["little", "big"]='little') -> bytes:
    if isinstance(data, float):
        return struct.pack(
            '{}f'.format('<' if byteorder == 'little' else '>'),
            data
        )

    if not isinstance(data, int):
        raise ValueError("p32: {} given ('int'/'float' expected)".format(type(data)))

    return (data & 0xffffffff).to_bytes(4, byteorder=byteorder)

def p64(data: Union[int, float], byteorder: Literal["little", "big"]='little') -> bytes:
    if isinstance(data, float):
        return struct.pack(
            '{}d'.format('<' if byteorder == 'little' else '>'),
            data
        )

    if not isinstance(data, int):
        raise ValueError("p64: {} given ('int'/'float' expected)".format(type(data)))

    return (data & 0xffffffffffffffff).to_bytes(8, byteorder=byteorder)
