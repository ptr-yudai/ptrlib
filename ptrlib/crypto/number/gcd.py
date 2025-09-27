"""This package provides the GCD functions.
"""
from typing import Tuple


def xgcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended GCD algorithm.

    Args:
        a (int): The first argument for extended GCD.
        b (int): The second argument for extended GCD.

    Returns:
        tuple: (d, x, y) such that ax + by = d = gcd(a, b).
    """
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

def gcd(a: int, b: int) -> int:
    """GCD algorithm.

    Args:
        a (int): The first argument for GCD.
        b (int): The second argument for GCD.

    Returns:
        int: GCD(a,b).
    """
    c = xgcd(a, b)[0]
    return c if c >= 0 else -c


__all__ = ['gcd', 'xgcd']
