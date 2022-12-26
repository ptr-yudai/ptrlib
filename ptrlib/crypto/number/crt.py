from logging import getLogger
from typing import List, Optional, Tuple, Union, overload
from .gcd import xgcd

logger = getLogger(__name__)


def crt_internal(pairs: List[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
    """ Chinese Remainder Theorem """
    N = 1
    result = 0
    for c, n in pairs: N *= n
    for c, n in pairs:
        m = N // n
        d, r, s = xgcd(n, m)
        if d != 1:
            logger.warning("Not pairwise co-prime")
            return None
        result += c * s * m
    return result % N, N

@overload
def crt(a: List[Tuple[int, int]], b: None=None) -> Optional[Tuple[int, int]]: ...

@overload
def crt(a: List[int], b: List[int]) -> Optional[Tuple[int, int]]: ...

def crt(a: Union[List[int], List[Tuple[int, int]]], b: Optional[List[int]]=None) -> Optional[Tuple[int, int]]:
    if (not isinstance(a, list)) \
       or (b is not None and not isinstance(b, list)) \
       or (b is not None and len(a) != len(b)):
        raise ValueError("Usage: crt([(c1,n1),(c2,n2),...]) or crt([c1,c2,...], [n1,n2,...])")

    if b is None:
        # crt([(c1,n1), (c2,n2), ...])
        pairs = a
    else:
        # crt([c1, c2, ...], [n1, n2, ...])
        pairs = list(zip(a, b))

    return crt_internal(pairs)

@overload
def CRT(a: List[Tuple[int, int]], b: None=None) -> Optional[Tuple[int, int]]: ...
@overload
def CRT(a: List[int], b: List[int]) -> Optional[Tuple[int, int]]: ...
def CRT(a: Union[List[int], List[Tuple[int, int]]], b: Optional[List[int]]=None) -> Optional[Tuple[int, int]]:
    return crt(a, b)

@overload
def chinese_remainder_theorem(a: List[Tuple[int, int]], b: None=None) -> Optional[Tuple[int, int]]: ...
@overload
def chinese_remainder_theorem(a: List[int], b: List[int]) -> Optional[Tuple[int, int]]: ...
def chinese_remainder_theorem(a: Union[List[int], List[Tuple[int, int]]], b: Optional[List[int]]=None) -> Optional[Tuple[int, int]]:
    return crt(a, b)
