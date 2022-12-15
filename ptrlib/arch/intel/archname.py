from logging import getLogger

logger = getLogger(__name__)


def is_arch_intel(arch, bits=None):
    """Check if architecture name string is intel series

    Args:
        arch (str): Architecture name
        bits (int): 32 or 64 (None by default)

    Returns:
        tuple: Returns tuple of canonicalized bits and name, or None.
    """
    arch = arch.lower().replace(' ', '').replace('_', '-')

    if bits is not None and bits != 16 and bits != 32 and bits != 64:
        logger.warn(f"Unknown bits: expected 16/32/64 but {bits} is given")
        raise ValueError("Unknown architecture '{}:{}'".format(arch, bits))

    if arch in ('intel', 'intel32', 'i386', 'x86'):
        # x86
        return True

    elif arch in ['intel64', 'x86-64', 'x64', 'amd', 'amd64']:
        # x86-64
        return True

    return False
