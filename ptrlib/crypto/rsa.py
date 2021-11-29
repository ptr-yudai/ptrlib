from logging import getLogger
from math import ceil
from fractions import Fraction
from ptrlib.crypto.number import *

logger = getLogger(__name__)

def hastads_broadcast_attack(e, pairs):
    """Hastad's Broadcast Attack

    If we have e ciphertext of same plaintext with different N,
    we can find the plaintext using Chinese Remainder Theorem.
    """
    if len(pairs) < e:
        logger.error("The number of (c,n) pairs is less than `e`.")
        logger.error("The result will be wrong unless `m` is small enough.")
    x, _ = chinese_remainder_theorem(pairs)
    return root(x, e)

def common_modulus_attack(cpair, epair, n):
    """Common Modulus Attack

    Given 2 (or more) ciphertext of same plaintext with different e,
    we can decrypt the ciphertext using Extended Euclid Algorithm.
    """
    if len(cpair) < 2 or len(epair) < 2:
        logger.warn("cpair and epair must have 2 or more elements.")
        return None

    c1, c2 = cpair[0], cpair[1]
    _, s1, s2 = xgcd(epair[0], epair[1])
    if s1 < 0:
        s1 = -s1
        c1 = inverse(c1, n)
    elif s2 < 0:
        s2 = -s2
        c2 = inverse(c2, n)
    return (pow(c1, s1, n) * pow(c2, s2, n)) % n

def lsb_leak_attack(lsb_oracle, n, e, c):
    """RSA LSB Leak Attack

    Given a cryptosystem such that:
    - Using the "textbook" RSA (RSA without pading)
    - We can give any ciphertexts to decrypt and can get the least significant bit of decrypted plaintext.
    - We can try to decrypt ciphertexts without limit
    we can break the ciphertext with LSB Leak Attack(We should make name more cool)

    Usage:
        plain = padding_oracle(lsb_oracle, N, e, C)

    The function lsb_oracle must return LSB (1 or 0).
    """
    logger = getLogger(__name__)

    L = n.bit_length()
    t = L // 100
    left, right = 0, n
    c2 = c
    i = 0
    while right - left > 1:
        m = Fraction(left + right, 2)
        c2 = (c2 * pow(2, e, n)) % n
        oracle = lsb_oracle(c2)
        if oracle == 1:
            left = m
        elif oracle == 0:
            right = m
        else:
            raise ValueError("The function `lsb_oracle` must return 1 or 0")
        i += 1
        if i % t == 0:
            logger.info("LSB Leak Attack {}/{}".format(i, L))
        assert(i <= L)
    return int(ceil(left))
