from logging import getLogger
from typing import Literal

logger = getLogger(__name__)


def is_arch_intel(arch: str) -> bool:
    """Check if architecture name string is Intel series

    Args:
        arch (str): Architecture name

    Returns:
        bool: Returns True if architecture name looks valid
    """
    return bit_by_arch_intel(arch) != -1

def bit_by_arch_intel(arch: str) -> Literal[32, 64, -1]:
    """Guess bits by architecture name string

    Args:
        arch (str): Architecture name

    Returns:
        int: -1 if invalid architecture, otherwise returns bits
    """
    arch = arch.lower().replace(' ', '').replace('_', '-')

    if arch in ('intel', 'intel32', 'i386', 'x86'):
        # x86
        return 32

    elif arch in ('intel64', 'x86-64', 'x64', 'amd', 'amd64'):
        # x86-64
        return 64

    return -1
