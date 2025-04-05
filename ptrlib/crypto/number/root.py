"""This package provides the root functions.
"""
from logging import getLogger
from typing import Tuple

logger = getLogger(__name__)


def rootrem(y: int, n: int) -> Tuple[int, int]:
    """ Calculate reminder n-th root.

    $x=trunc(y^(1/n)), r=y-x^n$

    Args:
        y (int): y of `rootrem[n]{y}`
        n (int): n of `rootrem[n]{y}`

    Returns:
        tuple: (x, r) where x is the n-th root of y and r is the remainder.

    Raises:
        ValueError: Cannot calculate the root.
    """
    if n == 0:
        raise ValueError("Zeroth root provided to rootrem")

    # TODO: Support negative argument with odd root
    if y < 0 or n < 0:
        raise ValueError("Negative argument provided to rootrem.")

    if abs(y) <= 1:
        # If y is 1, 0, or -1
        return y, 0

    u = 0
    t = 1 << (y.bit_length() // n + 1)
    if n == 1:
        # Who would use this?
        u = y
    elif n == 2:
        # Simplify sqrt loop
        while True:
            u, t = t, u
            t = (y // u + u) // 2
            if abs(t) >= abs(u):
                break
    else:
        # n != 2
        if n < 0:
            t = -t

        while True:
            u, t = t, u
            t = (y // pow(u, n-1) + u*(n-1)) // n
            if abs(t) >= abs(u):
                break

    return u, y - u**n

def root(y: int, n: int) -> int:
    """ Get n-th integer root of y.

    Args:
        y (int): y of `root[n]{y}`
        n (int): n of `root[n]{y}`

    Returns:
        int: The n-th integer root of y.

    Raises:
        ValueError: Cannot calculate the root.
    """
    return rootrem(y, n)[0]


__all__ = ['root', 'rootrem']
