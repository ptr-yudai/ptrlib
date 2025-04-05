"""This package defines the common modulus attack.
"""
from typing import List
from ptrlib.crypto.number.gcd import xgcd
from ptrlib.crypto.number.inverse import inverse


def common_modulus_attack(cpair: List[int], epair: List[int], n: int) -> int:
    """Common Modulus Attack

    Given 2 (or more) ciphertext of same plaintext with different e,
    we can decrypt the ciphertext using Extended Euclid Algorithm.

    Args:
        cpair (list): A pair of c.
        epair (list): A pair of e.

    Returns:
        int: Decrypted plaintext.
    """
    assert len(cpair) >= 2 or len(epair) >= 2, "cpair and epair must have 2 or more elements."

    # TODO: Use different pairs?
    c1, c2 = cpair[0], cpair[1]
    _, s1, s2 = xgcd(epair[0], epair[1])

    if s1 < 0:
        s1 = -s1
        c1 = inverse(c1, n)
    elif s2 < 0:
        s2 = -s2
        c2 = inverse(c2, n)

    return (pow(c1, s1, n) * pow(c2, s2, n)) % n


__all__ = ['common_modulus_attack']
