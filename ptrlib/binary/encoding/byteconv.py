"""This package provides byte and string converters.
"""
from typing import Tuple, List, Union
from logging import getLogger

logger = getLogger(__name__)


def bytes2str(data: Union[str, bytes]) -> str:
    """Convert bytes to str.

    Args:
        data (bytes): The data to convert.

    Returns:
        str: The converted data.
    """
    if isinstance(data, (bytes, bytearray)):
        return ''.join(list(map(chr, data)))

    if isinstance(data, str):
        return data

    raise TypeError(f"{type(data)} given ('bytes' expected)")

def str2bytes(data: Union[str, bytes]) -> bytes:
    """Convert str to bytes.

    Args:
        data (str): The data to convert.

    Returns:
        bytes: The converted data.
    """
    if isinstance(data, str):
        try:
            return bytes(list(map(ord, data)))
        except ValueError:
            return data.encode('utf-8')

    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)

    raise TypeError(f"{type(data)} given ('str' expected)")

def bytes2utf8(data: bytes) -> Tuple[str, bytes, List[bool]]:
    """Convert bytes to UTF-8 (!!! EXPERIMENTAL !!!)

    Convert byte array into UTF-8 string.
    This function also returns the leftover bytes that cannot not
    be interpreted as UTF-8.
    If it encounters an invalid character, the byte will be directly
    converted into a character just like `bytes2str` do.

    Args:
        data (bytes): Byte array to convert into UTF-8.

    Returns:
        tuple(str, bytes, list): UTF-8 string, leftover bytes, and marker
                                 indicating if each character is valid as UTF-8.
    """
    output = ''
    leftover = b''
    marker = []
    i = 0
    while i < len(data):
        c1 = data[i]
        if (c1 >> 5) & 0b111 == 0b110: # 2 bytes
            if i + 1 >= len(data):
                leftover = data[i:] # 1 byte left
                break
            c2 = data[i+1]
            if (c2 >> 6) & 0b11 == 0b10:
                try:
                    char = bytes([c1, c2]).decode('utf-8')
                    i += 2
                    marker.append(True)
                except UnicodeDecodeError:
                    # Sequence of `c1` `c2` is invalid as UTF-8
                    char = chr(c1)
                    i += 1
                    marker.append(False)
            else: # `c1` is invalid as UTF-8
                char = chr(c1)
                i += 1
                marker.append(False)
            output += char

        elif (c1 >> 4) & 0b1111 == 0b1110: # 3 bytes
            if i + 2 >= len(data):
                leftover = data[i:]
                break
            c2, c3 = data[i+1], data[i+2]
            if (c2 >> 6) & 0b11 == 0b10 and \
               (c3 >> 6) & 0b11 == 0b10:
                try:
                    char = bytes([c1, c2, c3]).decode('utf-8')
                    i += 3
                    marker.append(True)
                except UnicodeDecodeError:
                    # Sequence of `c1` `c2` `c3` is invalid as UTF-8
                    char = chr(c1)
                    i += 1
                    marker.append(False)
            else:
                char = chr(c1)
                i += 1
                marker.append(False)
            output += char

        elif (c1 >> 3) & 0b11111 == 0b11110: # 4 bytes
            if i + 3 >= len(data):
                leftover = data[i:]
                break
            c2, c3, c4 = data[i+1:i+4]
            if (c2 >> 6) & 0b11 == 0b10 and \
               (c3 >> 6) & 0b11 == 0b10 and \
               (c4 >> 6) & 0b11 == 0b10:
                try:
                    char = bytes([c1, c2, c3, c4]).decode('utf-8')
                    i += 4
                    marker.append(True)
                except UnicodeDecodeError:
                    # Sequence of `c1` `c2` `c3` `c4` is invalid as UTF-8
                    char = chr(c1)
                    i += 1
                    marker.append(False)
            else:
                char = chr(c1)
                i += 1
                marker.append(False)
            output += char

        else: # 1 byte or invalid
            output += chr(c1)
            i += 1
            marker.append(True)

    return output, leftover, marker

def bytes2hex(data: bytes) -> str:
    """Convert bytes to hex string
    """
    if not isinstance(data, bytes):
        raise TypeError(f"{type(data)} given ('bytes' expected)")

    return ''.join(list(map(lambda c: f'\\x{c:02x}', data)))

def str2hex(data: str) -> str:
    """Convert string to hex string
    """
    if not isinstance(data, str):
        raise TypeError(f"{type(data)} given ('str' expected)")

    return bytes2hex(str2bytes(data))


__all__ = ['bytes2str', 'str2bytes', 'bytes2utf8', 'bytes2hex', 'str2hex']
