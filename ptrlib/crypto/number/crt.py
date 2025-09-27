"""This package provides the chinese remainder theorem solver.
"""
import functools
import operator
from typing import List, Tuple
from .gcd import xgcd


def crt(clist: List[int], nlist: List[int]) -> Tuple[int, int]:
    """Chinese Remainder Theorem

    Args:
        clist (list): A list of integers to solve.
        nlist (list): A list of coprime divisors.

    Return:
        tuple: (x, n) where x is the solution and n = prod(nlist).

    Raises:
        ValueError: The list has integers with a nontrivial common factor.
    """
    assert isinstance(clist, list) and isinstance(nlist, list), \
        "crt([c1,c2,...], [n1,n2,...])"
    assert len(clist) == len(nlist), "len([c1,c2,...]) != len([n1,n2,...])"

    prod_n = functools.reduce(operator.mul, nlist, 1)
    result = 0

    for c, n in zip(clist, nlist):
        m = prod_n // n
        d, _, s = xgcd(n, m)
        if d != 1:
            raise ValueError("Not pairwise coprime")
        result += c * s * m
    return result % prod_n, prod_n


def chinese_remainder_theorem(clist: List[int], nlist: List[int]) -> Tuple[int, int]:
    """Chinese Remainder Theorem (Alias for `crt`).

    Args:
        clist (list): A list of integers to solve.
        nlist (list): A list of coprime divisors.

    Return:
        tuple: (x, n) where x is the solution and n = prod(nlist).

    Raises:
        ValueError: The list has integers with a nontrivial common factor.
    """
    return crt(clist, nlist)


__all__ = ['crt', 'chinese_remainder_theorem']
