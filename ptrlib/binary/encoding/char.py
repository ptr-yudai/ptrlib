"""This package provides some utilities for characters.
"""
from logging import getLogger
from typing import Union
from .byteconv import str2bytes

logger = getLogger(__name__)


def has_space(data: Union[str, bytes], warn: bool=False) -> bool:
    """Check if data has a whitespace of C locale

    Args:
        data (bytes): The data to check.
        warn (bool): Display warning if this parameter is set to true and a whitespace is found.

    Returns:
        bool: True if a whitespace is found, otherwise false.
    """
    if isinstance(data, str):
        data = str2bytes(data)

    # SPC, TAB, LF, VT, FF, CR
    whitespace = [0x20, 0x09, 0x0a, 0x0b, 0x0c, 0x0d]
    for i, c in enumerate(data):
        if c in whitespace:
            if warn:
                logger.warning("Whitespace '\\x%02x' at offset 0x%x", c, i)
            return True

    return False

def is_scanf_safe(data: Union[str, bytes], warn: bool=True) -> bool:
    """Check if data is safe for C scanf functions.

    Args:
        data (bytes): The data to check.
        warn (bool): Display warning if this parameter is set to true and a whitespace is found.

    Returns:
        bool: True if the data is safe for scanf.
    """
    return not has_space(data, warn)

def is_stream_safe(data: Union[str, bytes], warn: bool=True) -> bool:
    """Check if data is safe for C++ stream functions.

    Args:
        data (bytes): The data to check.
        warn (bool): Display warning if this parameter is set to true and a whitespace is found.

    Returns:
        bool: True if the data is safe for C++ stream.
    """
    return not has_space(data, warn)

def is_cin_safe(data: Union[str, bytes], warn: bool=True) -> bool:
    """Check if data is safe for C++ std::cin.

    Args:
        data (bytes): The data to check.
        warn (bool): Display warning if this parameter is set to true and a whitespace is found.

    Returns:
        bool: True if the data is safe for std::cin.
    """
    return not has_space(data, warn)

def is_fgets_safe(data: Union[str, bytes], warn: bool=True) -> bool:
    """Check if data is safe for the fgets function.

    Args:
        data (bytes): The data to check.
        warn (bool): Display warning if this parameter is set to true and a whitespace is found.

    Returns:
        bool: True if the data is safe for fgets.
    """
    if isinstance(data, str):
        data = str2bytes(data)

    offset = bytes(data).index(b'\n')
    if offset == -1:
        return True

    if warn:
        logger.warning("Newline '\\x0a' at offset 0x%x", offset)

    return False

def is_gets_safe(data: Union[str, bytes], warn: bool=True) -> bool:
    """Check if data is safe for the gets function.

    Args:
        data (bytes): The data to check.
        warn (bool): Display warning if this parameter is set to true and a whitespace is found.

    Returns:
        bool: True if the data is safe for gets.
    """
    return is_fgets_safe(data, warn)

def is_getline_safe(data: Union[str, bytes], warn: bool=True) -> bool:
    """Check if data is safe for the getline function.

    Args:
        data (bytes): The data to check.
        warn (bool): Display warning if this parameter is set to true and a whitespace is found.

    Returns:
        bool: True if the data is safe for getline.
    """
    return is_fgets_safe(data, warn)


__all__ = ['has_space', 'is_scanf_safe', 'is_stream_safe', 'is_cin_safe',
           'is_fgets_safe', 'is_gets_safe', 'is_getline_safe']
