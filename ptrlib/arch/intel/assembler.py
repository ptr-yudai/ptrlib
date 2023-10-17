import contextlib
import os
import platform
import subprocess
import tempfile
from logging import getLogger
from typing import Optional

logger = getLogger(__name__)


def __int_assemble_intel(code: bytes,
                         bits: int,
                         entry: str,
                         gcc_path: Optional[str]=None,
                         objcopy_path: Optional[str]=None) -> Optional[bytes]:
    from ptrlib.arch.common import which
    from .archname import is_arch_intel

    if gcc_path is None or objcopy_path is None:
        if is_arch_intel(platform.machine()):
            # intel --> intel: Use native compiler
            gcc_path = which('gcc')
            objcopy_path = which('objcopy')
        else:
            # not-intel --> intel: Use corss-platform compiler
            gcc_path = which('x86_64-linux-gnu-gcc')
            objcopy_path = which('x86_64-linux-gnu-objcopy')

        if gcc_path is None or objcopy_path is None:
            raise FileNotFoundError(
                "Install 'gcc' and 'objcopy', or specify path to them."
            )

    if bits == 32:
        code = b'.code32\n' + code

    fname_s   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.S'
    fname_o   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.o'
    fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.bin'
    with open(fname_s, 'wb') as f:
        f.write(code)

    with contextlib.suppress(FileNotFoundError):
        # Assemble
        cmd = [gcc_path, '-nostdlib', '-c', fname_s, '-o', fname_o]
        cmd.append('-Wl,--entry={}'.format(entry))
        if subprocess.Popen(cmd).wait() != 0:
            logger.warning("Assemble failed")
            os.unlink(fname_s)
            return

        # Extract
        cmd = [objcopy_path, '-O', 'binary', '-j', '.text', fname_o, fname_bin]
        if subprocess.Popen(cmd).wait() != 0:
            logger.warning("Extract failed")
            os.unlink(fname_s)
            os.unlink(fname_o)
            return

        with open(fname_bin, 'rb') as f:
            output = f.read()

        os.unlink(fname_s)
        os.unlink(fname_o)
        os.unlink(fname_bin)

        return output

def assemble_intel(code: bytes,
                   bits: int,
                   entry: str,
                   gcc_path: Optional[str]=None,
                   objcopy_path: Optional[str]=None) -> Optional[bytes]:
    """Assemble code to intel machine code

    Args:
       code (bytes): Assembly code
       bits (int): Bits of architecture
       entry (str): Entry point
    """
    candidate = __int_assemble_intel(code, bits, entry, gcc_path, objcopy_path)
    normalize = __int_assemble_intel(code + b'\n.byte 0x77', bits, entry, gcc_path, objcopy_path)

    # Remove padding inserted by some version of GCC
    if len(normalize) > len(candidate):
        for i in range(0x10):
            a = normalize[:len(normalize)-i]
            b = candidate[:len(normalize)-i-1]
            if a == b + b'\x77':
                return candidate[:len(normalize)-i-1]

    logger.error("Unexpected result by gcc and objcopy. The output may be wrong.")
    return candidate
