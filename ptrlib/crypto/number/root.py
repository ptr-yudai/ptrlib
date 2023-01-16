from logging import getLogger
from typing import Optional, Tuple, Union

logger = getLogger(__name__)


def rootrem(y: int, n: int) -> Union[Tuple[int, int], Tuple[None, None]]:
    """ Calculate reminder n-th root
    x=trunc(y^(1/n)), r=y-x^n

    Args:
        y (int): y of `rootrem[n]{y}`
        n (int): n of `rootrem[n]{y}`

    Returns:
        tuple: (x, r) where x is n-th root of y and r is the remainder
    """
    if n == 0:
        logger.warning("Zeroth root")
        return None, None

    # TODO: Support negative argument with odd root
    if y < 0 or n < 0:
        logger.warning("Negative argument")
        return None, None

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

def root(y: int, n: int) -> Optional[int]:
    """ Get n-th integer root of y

    Args:
        y (int): y of `root[n]{y}`
        n (int): n of `root[n]{y}`
    """
    return rootrem(y, n)[0]
