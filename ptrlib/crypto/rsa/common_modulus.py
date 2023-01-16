from logging import getLogger
from typing import List, Optional
from ptrlib.crypto.number.gcd import xgcd
from ptrlib.crypto.number.inverse import inverse

logger = getLogger(__name__)

def common_modulus_attack(cpair: List[int], epair: List[int], n: int) -> Optional[int]:
    """Common Modulus Attack

    Given 2 (or more) ciphertext of same plaintext with different e,
    we can decrypt the ciphertext using Extended Euclid Algorithm.
    """
    if len(cpair) < 2 or len(epair) < 2:
        logger.warning("cpair and epair must have 2 or more elements.")
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
