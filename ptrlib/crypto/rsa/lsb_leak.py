from fractions import Fraction
from logging import getLogger
from math import ceil
from typing import Callable
try:
    from typing import Literal
except:
    from typing_extensions import Literal

logger = getLogger(__name__)


def lsb_leak_attack(lsb_oracle: Callable[[int], Literal[0, 1]], n: int, e: int, c: int) -> int:
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
