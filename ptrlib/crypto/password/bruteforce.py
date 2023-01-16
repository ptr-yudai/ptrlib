from itertools import chain, product
from typing import List, Optional, Union

def bruteforce(minlen: Optional[int]=None, maxlen: Optional[int]=None, charset: Optional[Union[List[str], List[bytes], List[int], str, bytes]]=None):
    if minlen is None:
        minlen = 1
    if maxlen is None:
        maxlen = minlen

    if minlen <= 0 or maxlen <= 0:
        raise ValueError("Length must be positive integer")
    if maxlen < minlen:
        minlen, maxlen = maxlen, minlen

    if charset and len(charset) == 0:
        raise ValueError("Empty charset")

    if charset is None:
        charset = bytes([i for i in range(0x100)])
    elif isinstance(charset, list):
        if isinstance(charset[0], int):
            charset = bytes(charset)

    assert isinstance(charset, str) \
        or isinstance(charset, bytes) \
        or isinstance(charset, list)

    for length in range(minlen, maxlen+1):
        for candidate in product(charset, repeat=length):
            if isinstance(charset, bytes):
                yield bytes(candidate)
            else:
                if isinstance(candidate[0], bytes):
                    yield b''.join(candidate)
                else:
                    yield ''.join(candidate)
