from typing import List, Union
from ptrlib.binary.encoding import str2bytes
from logging import getLogger

logger = getLogger(__name__)


def xor(data: Union[str, bytes, List[int]], key: Union[int, str, bytes, List[int]]) -> bytes:
    assert isinstance(data, str) \
        or isinstance(data, bytes) \
        or isinstance(data, list)
    assert isinstance(key, str) \
        or isinstance(key, bytes) \
        or isinstance(key, int) \
        or isinstance(key, list)

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
            logger.warning("key (int) should be larger than 0 and less than 0x100 ({:x} given)".format(key))
        key = bytes([key & 0xff])
    
    result = b''
    for i in range(len(data)):
        result += bytes([data[i] ^ key[i % len(key)]])

    return result
