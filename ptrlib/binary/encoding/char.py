"""This package provides some utilities for characters.
"""
from logging import getLogger
from typing import TypeVar, Union
from .byteconv import str2bytes
from .dump import hexdump

logger = getLogger(__name__)


T = TypeVar('T', str, bytes)

def is_token(data: Union[str, bytes], warn: bool=True) -> bool:
    """Check if data is a valid token for scanf(%s), cin, or other C++ stream.

    Args:
        data (bytes): The data to check.
        warn (bool): Display warning if this parameter is set to true and a whitespace is found.

    Returns:
        bool: True if no whitespace or line is found, otherwise false.
    """
    if isinstance(data, str):
        data = str2bytes(data)

    # SPC, TAB, LF, VT, FF, CR
    errs = []
    for i, c in enumerate(data):
        if c in (0x20, 0x09, 0x0a, 0x0b, 0x0c, 0x0d):
            if not warn:
                return False
            errs.append((i, c))

    if errs:
        hexdump(data)
        for i, c in errs:
            logger.warning("Whitespace '\\x%02x' at offset 0x%x", c, i)
        return False

    return True

def is_line(data: Union[str, bytes], warn: bool=True) -> bool:
    """Check if data is safe for the fgets function.

    Args:
        data (bytes): The data to check.
        warn (bool): Display warning if this parameter is set to true and a whitespace is found.

    Returns:
        bool: True if the data is safe for fgets.
    """
    if isinstance(data, str):
        data = str2bytes(data)

    errs = []
    for i, c in enumerate(data):
        if c == 0x0a:
            if not warn:
                return False
            errs.append((i, c))

    if errs:
        hexdump(data)
        for i, c in errs:
            logger.warning("Newline '\\x%02x' at offset 0x%x", c, i)
        return False

    return True

def assert_token(data: T, warn: bool=True) -> T:
    """Assert if data is a valid token for scanf(%s), cin, or other C++ stream.

    Args:
        data (bytes): Data to check.
        warn (bool): Display warning if this parameter is set to true and a whitespace is found.

    Raises:
        ValueError: If data is not a valid token.

    Returns:
        bytes: Input data.
    """
    if not is_token(data, warn):
        raise ValueError("Data is not a token")
    return data

def assert_line(data: T, warn: bool=True) -> T:
    """Check if data is a valid line for gets, fgets, or getline.

    Args:
        data (bytes): Data to check.
        warn (bool): Display warning if this parameter is set to true and a whitespace is found.

    Raises:
        ValueError: If data is not a valid line.

    Returns:
        bytes: Input data.
    """
    if not is_line(data, warn):
        raise ValueError("Data is not a line")
    return data


__all__ = ['is_token', 'is_line', 'assert_token', 'assert_line']
