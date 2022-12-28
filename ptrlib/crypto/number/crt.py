from logging import getLogger
from .gcd import xgcd

logger = getLogger(__name__)


def crt_internal(pairs):
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

def crt(a, b=None):
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

def CRT(a, b=None):
    return crt(a, b)

def chinese_remainder_theorem(a, b=None):
    return crt(a, b)
