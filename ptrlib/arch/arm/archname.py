from logging import getLogger

logger = getLogger(__name__)


def is_arch_arm(arch, bits=None):
    """Check if architecture name string is ARM series

    Args:
        arch (str): Architecture name
        bits (int): 32 or 64 (None by default)

    Returns:
        tuple: Returns tuple of canonicalized bits and name, or None.
    """
    arch = arch.lower().replace(' ', '').replace('_', '-')

    if bits is not None and bits != 16 and bits != 32 and bits != 64:
        logger.warning(f"Unknown bits: expected 16/32/64 but {bits} is given")
        raise ValueError("Unknown architecture '{}:{}'".format(arch, bits))

    if arch in ('arm', 'arm32', 'aarch32'):
        # ARM
        return True

    elif arch in ['aarch', 'arm64', 'aarch64']:
        # AArch64
        return True

    return False
