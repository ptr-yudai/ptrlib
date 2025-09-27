"""This package provides some utilities for bitwise conversion.
"""
from logging import getLogger

logger = getLogger(__name__)


def bit_reflect(n: int, bits: int) -> int:
    """Bitwise reverse.

    Args:
        n (int): An integer value.
        bits (int): The maximum bits of the value.

    Returns:
        int: An integer reversed in bitwise.
    """
    m = 0
    for i in range(bits):
        m = (m << 1) | ((n >> i) & 1)
    return m
