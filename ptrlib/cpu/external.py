"""This package provides some utilities to suggest cross-platform program path.
"""
from logging import getLogger
import platform
import shutil
from ptrlib.types import PtrlibArchT, PtrlibBitsT

logger = getLogger(__name__)


def _cross_arch_tool(toolname: str, arch: PtrlibArchT, bits: PtrlibBitsT) -> str:
    """Get the full path to GCC for a specific architecture.

    Args:
        toolname (tsr): The name of the tool to find.
        arch (str): The name of the target architecture.
        bits (int): The bits of the target architecture.

    Returns:
        str: The full path to compiler.

    Raises:
        FileNotFoundError: No compiler found.
    """
    path = None
    hint = ''
    machine = platform.machine().lower()

    if machine in ('x86_64', 'x64', 'x86', 'i386', 'i686'):
        if arch == 'intel':
            path = shutil.which(toolname)
            hint = toolname

        elif arch == 'arm':
            if bits == 32:
                path = shutil.which(f'arm-linux-gnueabi-{toolname}') \
                    or shutil.which(f'arm-linux-gnueabihf-{toolname}')
                hint = f'{toolname}-arm-linux-gnueabi'
            else:
                path = shutil.which(f'aarch64-linux-gnu-{toolname}')
                hint = f'{toolname}-aarch64-linux-gnu'

        elif arch == 'mips':
            if bits == 32:
                path = shutil.which(f'mipsel-linux-gnu-{toolname}')
                hint = f'{toolname}-mipsel-linux-gnu'
            else:
                path = shutil.which(f'mips64el-linux-gnuabi64-{toolname}')
                hint = f'{toolname}-mips64el-linux-gnuabi64'

        elif arch == 'sparc':
            if bits == 32:
                path = shutil.which(f'sparc-linux-gnu-{toolname}')
                hint = f'{toolname}-sparc-linux-gnu'
            else:
                path = shutil.which(f'sparc64-linux-gnu-{toolname}')
                hint = f'{toolname}-sparc64-linux-gnu'

        elif arch == 'risc-v':
            if bits == 32:
                path = shutil.which(f'riscv-linux-gnu-{toolname}')
                hint = f'{toolname}-riscv-linux-gnu'
            else:
                path = shutil.which(f'riscv64-linux-gnu-{toolname}')
                hint = f'{toolname}-riscv64-linux-gnu'

    else:
        logger.error("Your environment '%s' is not supported yet.", machine)

    if path is None:
        if hint:
            hint = f' Install it with `apt install {hint}`.'
        raise FileNotFoundError(f'Cannot find GCC for {arch}-{bits}.{hint}')

    return path

def objcopy(arch: PtrlibArchT, bits: PtrlibBitsT) -> str:
    """Get the full path to objcopy for a specific architecture.

    Args:
        arch (str): The name of the target architecture.
        bits (int): The bits of the target architecture.

    Returns:
        str: The full path to objcopy.

    Raises:
        FileNotFoundError: `objcopy` not found.
    """
    return _cross_arch_tool('objcopy', arch, bits)

def objdump(arch: PtrlibArchT, bits: PtrlibBitsT) -> str:
    """Get the full path to objdump for a specific architecture.

    Args:
        arch (str): The name of the target architecture.
        bits (int): The bits of the target architecture.

    Returns:
        str: The full path to objdump.

    Raises:
        FileNotFoundError: `objdump` not found.
    """
    return _cross_arch_tool('objdump', arch, bits)

def gcc(arch: PtrlibArchT, bits: PtrlibBitsT) -> str:
    """Get the full path to GCC for a specific architecture.

    Args:
        arch (str): The name of the target architecture.
        bits (int): The bits of the target architecture.

    Returns:
        str: The full path to compiler.

    Raises:
        FileNotFoundError: No compiler found.
    """
    return _cross_arch_tool('gcc', arch, bits)

def nasm() -> str:
    """Get the full path to NASM.

    Returns:
        str: The full path to NASM assembler.

    Raises:
        FileNotFoundError: NASM not found.
    """
    path = shutil.which('nasm')
    if path is None:
        raise FileNotFoundError("Cannot find NASM. Install it with `apt install nasm`.")

    return path

__all__ = ['gcc', 'objcopy', 'nasm']
