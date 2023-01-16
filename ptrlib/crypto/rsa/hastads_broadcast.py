from logging import getLogger
from typing import List
from ptrlib.crypto.number import chinese_remainder_theorem, root

logger = getLogger(__name__)


def hastads_broadcast_attack(e: int, pairs: List[int]) -> int:
    """Hastad's Broadcast Attack

    If we have e ciphertext of same plaintext with different N,
    we can find the plaintext using Chinese Remainder Theorem.
    """
    if len(pairs) < e:
        logger.error("The number of (c,n) pairs is less than `e`.")
        logger.error("The result will be wrong unless `m` is small enough.")

    x, _ = chinese_remainder_theorem(pairs)
    return root(x, e)
