from logging import getLogger
from .gcd import xgcd

logger = getLogger(__name__)


def inverse(a, n):
    """ Inverse modulo """
    g, x, y = xgcd(a, n)
    if g != 1:
        logger.warning("No modular inverse")
        return None
    return x % n
