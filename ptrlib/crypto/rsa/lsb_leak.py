"""This package defines the LSB leak attack.
"""
from fractions import Fraction
from logging import getLogger
from math import ceil
from typing import Callable, Literal

logger = getLogger(__name__)


def lsb_leak_attack(lsb_oracle: Callable[[int], Literal[0, 1]], n: int, e: int, c: int) -> int:
    """RSA LSB Leak Attack

    Given a cryptosystem such that:
    - Using the "textbook" RSA (RSA without pading)
    - We can give any ciphertexts to decrypt and can get the least significant bit of decrypted plaintext.
    - We can try to decrypt ciphertexts without limit
    we can break the ciphertext with LSB Leak Attack(We should make name more cool)

    Args:
        lsb_oracle (function): An oracle that accepts a ciphertext and returns the LSB of the plaintext.
        n (int): Modulus.
        e (int): Exponent.
        c (int): Ciphertext.

    Returns:
        int: Decrypted plaintext.

    Examples:
        ```
        plain = padding_oracle(lsb_oracle, N, e, C)
        ```
    """
    l = n.bit_length()
    t = l // 100
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
            logger.info("LSB leak attack {i}/{l}")

        assert i <= l, "Invalid oracle"

    return int(ceil(left))
