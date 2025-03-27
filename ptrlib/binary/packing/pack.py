"""This package provides some helpders to pack data. 
"""
import struct
from logging import getLogger
from typing import Union
from ptrlib.annotation import PtrlibEndiannessT

logger = getLogger(__name__)


def p8(data: int) -> bytes:
    """Pack a 1-byte value.

    Args:
        data (int): A value to pack into a byte.
                    The value is converted to unsigned if it's negative.

    Returns:
        bytes: A byte.
    """
    if not isinstance(data, int):
        raise TypeError(f"p8: {type(data)} given ('int' expected)")

    if data < 0:
        data = (-data ^ 0xff) + 1

    if data > 0xff:
        logger.warning("Truncating overflow (%d > 0xff)", data)

    return (data & 0xff).to_bytes(1, byteorder='little')

def p16(data: int, byteorder: PtrlibEndiannessT='little') -> bytes:
    """Pack a 2-byte value.

    Args:
        data (int): A value to pack into a word.
                    The value is converted to unsigned if it's negative.

    Returns:
        bytes: A word of bytes.
    """
    if not isinstance(data, int):
        raise TypeError(f"p16: {type(data)} given ('int' expected)")

    if data < 0:
        data = (-data ^ 0xffff) + 1

    if data > 0xffff:
        logger.warning("Truncating overflow (%d > 0xffff)", data)

    return (data & 0xffff).to_bytes(2, byteorder=byteorder)

def p32(data: Union[int, float], byteorder: PtrlibEndiannessT='little') -> bytes:
    """Pack a 4-byte value.

    Args:
        data (int): A value to pack into a dword.
                    The value is converted to unsigned if it's negative.

    Returns:
        bytes: A dword of bytes.
    """
    if isinstance(data, float):
        return struct.pack('<f' if byteorder == 'little' else '>f', data)

    if not isinstance(data, int):
        raise TypeError(f"p32: {type(data)} given ('int'/'float' expected)")

    if data < 0:
        data = (-data ^ 0xffffffff) + 1

    if data > 0xffffffff:
        logger.warning("Truncating overflow (%d > 0xffffffff)", data)

    return (data & 0xffffffff).to_bytes(4, byteorder=byteorder)

def p64(data: Union[int, float], byteorder: PtrlibEndiannessT='little') -> bytes:
    """Pack a 8-byte value.

    Args:
        data (int): A value to pack into a qword.
                    The value is converted to unsigned if it's negative.

    Returns:
        bytes: A qword of bytes.
    """
    if isinstance(data, float):
        return struct.pack(
            f"{'<' if byteorder == 'little' else '>'}d",
            data
        )

    if not isinstance(data, int):
        raise TypeError(f"p64: {type(data)} given ('int'/'float' expected)")

    if data < 0:
        data = (-data ^ 0xffffffffffffffff) + 1

    if data > 0xffffffffffffffff:
        logger.warning("Truncating overflow (%d > 0xffffffffffffffff)", data)

    return (data & 0xffffffffffffffff).to_bytes(8, byteorder=byteorder)


__all__ = ['p8', 'p16', 'p32', 'p64']
