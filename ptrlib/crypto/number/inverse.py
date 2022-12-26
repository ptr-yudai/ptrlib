from logging import getLogger
from typing import Optional
from .gcd import xgcd

logger = getLogger(__name__)


def inverse(a: int, n: int) -> Optional[int]:
    """ Inverse modulo """
    g, x, _ = xgcd(a, n)
    if g != 1:
        logger.warning("No modular inverse")
        return None
    return x % n
