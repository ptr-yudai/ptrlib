from typing import Tuple
from logging import getLogger

logger = getLogger(__name__)


def bytes2str(data: bytes) -> str:
    """Convert bytes to str
    """
    if isinstance(data, bytes):
        return ''.join(list(map(chr, data)))
    else:
        raise ValueError("{} given ('bytes' expected)".format(type(data)))

def str2bytes(data: str) -> bytes:
    """Convert str to bytes
    """
    if isinstance(data, str):
        try:
            return bytes(list(map(ord, data)))
        except ValueError:
            return data.encode('utf-8')
    else:
        raise ValueError("{} given ('str' expected)".format(type(data)))

def bytes2utf8(data: bytes) -> Tuple[str, bytes]:
    """Convert bytes to UTF-8

    Convert byte array into UTF-8 string.
    This function also returns the leftover bytes that cannot not
    be interpreted as UTF-8.
    If it encounters an invalid character, the byte will be directly
    converted into a character just like `bytes2str` do.

    Args:
        data: Byte array to convert into UTF-8 (bytes)

    Returns:
        tuple(str, bytes): UTF-8 string and leftover bytes
    """
    output = ''
    leftover = b''
    i = 0
    while i < len(data):
        c1 = data[i]
        if (c1 >> 5) & 0b111 == 0b110: # 2 bytes
            if i + 1 >= len(data):
                leftover = data[i:]
                break
            c2 = data[i+1]
            if (c2 >> 6) & 0b11 == 0b10:
                char = bytes([c1, c2]).decode('utf-8')
                i += 2
            else:
                char = chr(c1)
                i += 1
            output += char

        elif (c1 >> 4) & 0b1111 == 0b1110: # 3 bytes
            if i + 2 >= len(data):
                leftover = data[i:]
                break
            c2, c3 = data[i+1], data[i+2]
            if (c2 >> 6) & 0b11 == 0b10 and \
               (c3 >> 6) & 0b11 == 0b10:
                char = bytes([c1, c2, c3]).decode('utf-8')
                i += 3
            else:
                char = chr(c1)
                i += 1
            output += char

        elif (c1 >> 3) & 0b11111 == 0b11110: # 4 bytes
            if i + 3 >= len(data):
                leftover = data[i:]
                break
            c2, c3, c4 = data[i+1:i+4]
            if (c2 >> 6) & 0b11 == 0b10 and \
               (c3 >> 6) & 0b11 == 0b10 and \
               (c4 >> 6) & 0b11 == 0b10:
                char = bytes([c1, c2, c3, c4]).decode('utf-8')
                i += 4
            else:
                char = chr(c1)
                i += 1
            output += char

        else: # 1 byte or invalid
            output += chr(c1)
            i += 1

    return output, leftover
