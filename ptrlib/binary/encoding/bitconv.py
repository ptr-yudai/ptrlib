from logging import getLogger

logger = getLogger(__name__)


def bit_reflect(n: int, bits: int) -> int:
    """Reverse bits
    """
    m = 0
    for i in range(bits):
        m = (m << 1) | ((n >> i) & 1)
    return m
