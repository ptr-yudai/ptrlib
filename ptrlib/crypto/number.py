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

def rootrem(y, n):
    """ Calculate reminder n-th root
    x=trunc(y^(1/n)), r=y-x^n

    Args:
        y (int): y of `rootrem[n]{y}`
        n (int): n of `rootrem[n]{y}`

    Returns:
        tuple: (x, r) where x is n-th root of y and r is the remainder
    """
    if n == 0:
        logger.warning("Zeroth root")
        return None, None

    # [TODO] Support negative argument with odd root
    if y < 0 or n < 0:
        logger.warning("Negative argument")
        return None, None

    if abs(y) <= 1:
        # If y is 1, 0, or -1
        return y, 0

    u = 0
    t = 1 << (y.bit_length() // n + 1)
    if n == 1:
        # Who would use this?
        u = y
    elif n == 2:
        # Simplify sqrt loop
        while True:
            u, t = t, u
            t = (y // u + u) // 2
            if abs(t) >= abs(u):
                break
    else:
        # n != 2
        if n < 0:
            t = -t

        while True:
            u, t = t, u
            t = (y // pow(u, n-1) + u*(n-1)) // n
            if abs(t) >= abs(u):
                break

    return u, y - u**n

def root(y, n):
    """ Get n-th integer root of y

    Args:
        y (int): y of `root[n]{y}`
        n (int): n of `root[n]{y}`
    """
    return rootrem(y, n)[0]

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
