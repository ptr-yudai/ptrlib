import gmpy2
import random

_ctx = gmpy2.get_context().precision = 4096

def gen_prime(bits):
    """ Generate a random prime """
    while True:
        n = random.getrandbits(bits)
        if gmpy2.is_prime(n):
            return n

def is_prime(n):
    """ Check if a number is prime """
    return gmpy2.is_prime(n)

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
