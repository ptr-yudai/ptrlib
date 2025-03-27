"""This package provides some helpders to unpack data. 
"""
import struct
from logging import getLogger
from typing import Union
from ptrlib.annotation import PtrlibEndiannessT
from ptrlib.binary.encoding.byteconv import str2bytes

logger = getLogger(__name__)


def u8(data: Union[str, bytes], signed: bool=False) -> int:
    """Unpack a byte into integer.

    Args:
        data (bytes): A byte to unpack.

    Returns:
        int: The unpacked value.
    """
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError(f"u8: {type(data)} given ('bytes' expected)")

    return int.from_bytes(data, 'big', signed=signed)

def u16(data: Union[str, bytes], byteorder: PtrlibEndiannessT="little", signed: bool=False) -> int:
    """Unpack a word into integer.

    Args:
        data (bytes): A word of bytes to unpack.

    Returns:
        int: The unpacked value.
    """
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError(f"u16: {type(data)} given ('bytes' expected)")

    return int.from_bytes(data, byteorder=byteorder, signed=signed)

def u32(data: Union[str, bytes], byteorder: PtrlibEndiannessT="little", signed: bool=False) -> int:
    """Unpack a dword into integer

    Args:
        data (bytes): A dword of bytes to unpack.

    Returns:
        int: The unpacked value.
    """
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError(f"u32: {type(data)} given ('bytes' expected)")

    return int.from_bytes(data, byteorder=byteorder, signed=signed)

def u32f(data: Union[str, bytes], byteorder: PtrlibEndiannessT="little") -> float:
    """Unpack q dword into float

    Args:
        data (bytes): A dword of bytes to unpack.

    Returns:
        float: The unpacked value.
    """
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError(f"u32f: {type(data)} given ('bytes' expected)")

    return struct.unpack('<f' if byteorder == 'little' else '>f', data)[0]

def u64(data: Union[str, bytes], byteorder: PtrlibEndiannessT='little', signed: bool=False) -> int:
    """Unpack a qword into integer

    Args:
        data (bytes): A qword of bytes to unpack.

    Returns:
        int: The unpacked value.
    """
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError(f"u64: {type(data)} given ('bytes' expected)")

    return int.from_bytes(data, byteorder=byteorder, signed=signed)

def u64f(data: Union[str, bytes], byteorder: PtrlibEndiannessT="little") -> float:
    """Unpack a qword into float

    Args:
        data (bytes): A qword of bytes to unpack.

    Returns:
        int: The unpacked value.
    """
    if isinstance(data, str):
        data = str2bytes(data)

    if not isinstance(data, bytes):
        raise ValueError(f"u64f: {type(data)} given ('bytes' expected)")

    return struct.unpack('<d' if byteorder == 'little' else '>d', data)[0]


__all__ = ['u8', 'u16', 'u32', 'u64', 'u32f', 'u64f']
