"""This package provides a generic XOR implementation.
"""
from logging import getLogger
from typing import List, Union
from ptrlib.binary.encoding import str2bytes

logger = getLogger(__name__)


def xor(data: Union[str, bytes, List[int]], key: Union[int, str, bytes, List[int]]) -> bytes:
    """Xor data with a key.

    Args:
        data (Union[str, bytes, List[int]]): The plaintext.
        key (Union[str, bytes, int, List[int]]): The key.
            The key is used repeatedly if the key length is shorter than the data length.

    Returns:
        bytes: The encrypted data.

    Examples:
        ```
        xor("Hello, World", "key")
        xor(b"Hello, World", 47)
        xor("Hello", b"ALongKeyWillBeTruncated")
        xor([1,2,3,4,5], [0xaa,0x55])
        ```
    """
    assert isinstance(data, (str, bytes, bytearray, list))
    assert isinstance(key, (str, bytes, bytearray, int, list))

    if isinstance(data, str):
        data = str2bytes(data)
    elif isinstance(data, list):
        data = bytes(data)

    if isinstance(key, str):
        key = str2bytes(key)
    elif isinstance(key, list):
        key = bytes(key)
    elif isinstance(key, int):
        if key < 0 or key > 0xff:
            logger.warning("key (int) should be in [0x00, 0xff] (0x%x given)", key)
        key = bytes([key & 0xff])

    result = b''
    for i, c in enumerate(data):
        result += bytes([c ^ key[i % len(key)]])

    return result


__all__ = ['xor']
