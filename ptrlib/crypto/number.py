import gmpy2
import random

_ctx = gmpy2.get_context().precision = 4096

def gen_prime(bits):
    while True:
        n = random.getrandbits(bits)
        if gmpy2.is_prime(n):
            return n

def chinese_remainder_theorem(pairs):
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

def xgcd(a, b):
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

def inverse(a, n):
    g, x, y = xgcd(a, n)
    if g != 1:
        logger.warn("No modular inverse")
        return None
    return x % n
