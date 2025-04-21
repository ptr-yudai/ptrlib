"""This package provides some helpders to pack data. 
"""
import struct
from logging import getLogger
from typing import Union
from ptrlib.types import PtrlibEndiannessT, PtrlibIntLikeT

logger = getLogger(__name__)


def p8(data: PtrlibIntLikeT) -> bytes:
    """Pack a 1-byte value.

    Args:
        data (int): A value to pack into a byte.
                    The value is converted to unsigned if it's negative.

    Returns:
        bytes: A byte.
    """
    idata = int(data)
    if idata < 0:
        idata = (-idata ^ 0xff) + 1

    if idata > 0xff:
        logger.warning("Truncating overflow (%d > 0xff)", idata)

    return (idata & 0xff).to_bytes(1, byteorder='little')

def p16(data: PtrlibIntLikeT, byteorder: PtrlibEndiannessT='little') -> bytes:
    """Pack a 2-byte value.

    Args:
        data (int): A value to pack into a word.
                    The value is converted to unsigned if it's negative.

    Returns:
        bytes: A word of bytes.
    """
    idata = int(data)
    if idata < 0:
        idata = (-idata ^ 0xffff) + 1

    if idata > 0xffff:
        logger.warning("Truncating overflow (%d > 0xffff)", idata)

    return (idata & 0xffff).to_bytes(2, byteorder=byteorder)

def p32(data: Union[PtrlibIntLikeT, float], byteorder: PtrlibEndiannessT='little') -> bytes:
    """Pack a 4-byte value.

    Args:
        data (int): A value to pack into a dword.
                    The value is converted to unsigned if it's negative.

    Returns:
        bytes: A dword of bytes.
    """
    if isinstance(data, float):
        return struct.pack('<f' if byteorder == 'little' else '>f', data)

    idata = int(data)
    if idata < 0:
        idata = (-idata ^ 0xffffffff) + 1

    if idata > 0xffffffff:
        logger.warning("Truncating overflow (%d > 0xffffffff)", idata)

    return (idata & 0xffffffff).to_bytes(4, byteorder=byteorder)

def p64(data: Union[PtrlibIntLikeT, float], byteorder: PtrlibEndiannessT='little') -> bytes:
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

    idata = int(data)
    if idata < 0:
        idata = (-idata ^ 0xffffffffffffffff) + 1

    if idata > 0xffffffffffffffff:
        logger.warning("Truncating overflow (%d > 0xffffffffffffffff)", idata)

    return (idata & 0xffffffffffffffff).to_bytes(8, byteorder=byteorder)


__all__ = ['p8', 'p16', 'p32', 'p64']
