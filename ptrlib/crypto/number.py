from logging import getLogger
import random

logger = getLogger(__name__)

def chinese_remainder_theorem(pairs):
    """ Chinese Remainder Theorem """
    N = 1
    result = 0
    for c, n in pairs: N *= n
    for c, n in pairs:
        m = N // n
        d, r, s = xgcd(n, m)
        if d != 1:
            logger.warn("Not pairwise co-prime")
            return None
        result += c * s * m
    return result % N, N

def crt(pairs):
    # wrapper for chinese_remainder_theorem
    return chinese_remainder_theorem(pairs)

def xgcd(a, b):
    """ Extended GCD algorithm """
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

def inverse(a, n):
    """ Inverse modulo """
    g, x, y = xgcd(a, n)
    if g != 1:
        logger.warn("No modular inverse")
        return None
    return x % n
