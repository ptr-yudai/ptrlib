"""This package provides some primitive operations.
"""
from logging import getLogger
from typing import Any, List, TypeVar

logger = getLogger(__name__)

_T = TypeVar("_T", int, str, bytes, List[Any])


def rol(data: _T, n: int, bits: int=32) -> _T:
    """Rotate left.

    Args:
        data (Union[int, str, bytes, List[Any]]): A value or data to rotate.
        n (int): The number of rotation.
        bits (int, optional): The maximum size of the rotation.
                              This parameter is effective only if the data type is integer.

    Returns:
        Union[int,str,bytes,List[Any]]: The rotated value.
    """
    if isinstance(data, int):
        if data.bit_length() > bits:
            logger.warning("A %d-bit value given (Max bits=%d expected)", data.bit_length(), bits)
            data &= ((1 << bits) - 1)
        return ((data << n) | (data >> (bits - n))) & ((1 << bits) - 1)

    if isinstance(data, (str, bytes, bytearray, list)):
        return data[n:] + data[:n]

    raise ValueError(f"{type(data)} given ('int'/'str'/'bytes'/'list' expected)")

def ror(data: _T, n: int, bits: int=32) -> _T:
    """Rotate right.

    Args:
        data (Union[int, str, bytes, List[Any]]): A value or data to rotate.
        n (int): The number of rotation.
        bits (int, optional): The maximum size of the rotation.
                              This parameter is effective only if the data type is integer.

    Returns:
        Union[int,str,bytes,List[Any]]: The rotated value.
    """
    if isinstance(data, int):
        if data.bit_length() > bits:
            logger.warning("A %d-bit value given (Max bits=%d expected)", data.bit_length(), bits)
            data &= ((1 << bits) - 1)
        return ((data >> n) | ((data & ((1 << n) - 1)) << (bits - n))) & ((1 << bits) - 1)

    if isinstance(data, (str, bytes, bytearray, list)):
        return data[-n:] + data[:-n]

    raise ValueError(f"{type(data)} given ('int'/'str'/'bytes'/'list' expected)")


__all__ = ['rol', 'ror']
