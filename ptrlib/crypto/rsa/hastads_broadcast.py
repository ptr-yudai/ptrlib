"""This package defines Hastad's Broadcast Attack.
"""
from logging import getLogger
from typing import List
from ptrlib.crypto.number import chinese_remainder_theorem, root

logger = getLogger(__name__)


def hastads_broadcast_attack(e: int, clist: List[int], nlist: List[int]) -> int:
    """Hastad's Broadcast Attack

    If we have e ciphertext of same plaintext with different N,
    we can find the plaintext using Chinese Remainder Theorem.

    Args:
        e (int): Exponent.
        clist (list): A list of ciphertext.
        nlist (list): A list of modulus.

    Return:
        int: Decrypted plaintext.

    Raises:
        ValueError: The list has integers with a nontrivial common factor.
    """
    if len(clist) < e:
        logger.warning("The size of (c,n) pairs is less than `e`. "
                       "The result will be wrong unless `m` is small enough.")

    x, _ = chinese_remainder_theorem(clist, nlist)
    return root(x, e)


__all__ = ['hastads_broadcast_attack']
