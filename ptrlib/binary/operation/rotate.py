from logging import getLogger
from typing import Any, List, TypeVar

logger = getLogger(__name__)

_T = TypeVar("_T", int, str, bytes, List[Any])

def rol(data: _T, n: int, bits: int=32) -> _T:
    """Rotate left
    """
    if isinstance(data, int):
        if data.bit_length() > bits:
            logger.warning("data of bits={} given (bits={} expected)".format(data.bit_length(), bits))
            data &= ((1 << bits) - 1)
        return ((data << n) | (data >> (bits - n))) & ((1 << bits) - 1)

    elif isinstance(data, str) \
         or isinstance(data, bytes) \
         or isinstance(data, list):
        return data[n:] + data[:n]

    else:
        raise ValueError("{} given ('int'/'str'/'bytes'/'list' expected)".format(type(data)))

def ror(data: _T, n: int, bits: int=32) -> _T:
    """Rotate right
    """
    if isinstance(data, int):
        if data.bit_length() > bits:
            logger.warning("data of bits={} given (bits={} expected)".format(data.bit_length(), bits))
            data &= ((1 << bits) - 1)
        return ((data >> n) | ((data & ((1 << n) - 1)) << (bits - n))) & ((1 << bits) - 1)

    elif isinstance(data, str) \
         or isinstance(data, bytes) \
         or isinstance(data, list):
        return data[-n:] + data[:-n]

    else:
        raise ValueError("{} given ('int'/'str'/'bytes'/'list' expected)".format(type(data)))
