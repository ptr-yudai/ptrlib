"""This package provides the inverse function.
"""
from logging import getLogger
from .gcd import xgcd

logger = getLogger(__name__)


def inverse(a: int, n: int) -> int:
    """Inverse modulo.

    Args:
        a (int): The number to calculate inverse.
        n (int): Modulo.
    """
    g, x, _ = xgcd(a, n)
    if g != 1:
        raise ValueError(f"No modular inverse found for {a} (mod {n})")
    return x % n


__all__ = ['inverse']
