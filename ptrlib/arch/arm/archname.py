from logging import getLogger
from typing import Literal

logger = getLogger(__name__)


def is_arch_arm(arch: str) -> bool:
    """Check if architecture name string is ARM series

    Args:
        arch (str): Architecture name

    Returns:
        bool: Returns True if architecture name looks valid
    """
    return bit_by_arch_arm(arch) != -1

def bit_by_arch_arm(arch: str) -> Literal[32, 64, -1]:
    """Guess bits by architecture name string

    Args:
        arch (str): Architecture name

    Returns:
        int: -1 if invalid architecture, otherwise returns bits
    """
    arch = arch.lower().replace(' ', '').replace('_', '-')

    if arch in ('arm', 'arm32', 'aarch32'):
        # ARM
        return 32

    elif arch in ('aarch', 'arm64', 'aarch64'):
        # AArch64
        return 64

    return -1
    
