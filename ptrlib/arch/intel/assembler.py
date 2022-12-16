import contextlib
import os
import platform
import subprocess
import tempfile
from logging import getLogger

logger = getLogger(__name__)


def assemble_intel(code, bits, entry, gcc_path=None, objcopy_path=None):
    """Assemble code to intel machine code

    Args:
       code (bytes): Assembly code
       bits (int): Bits of architecture
       entry (bytes): Entry point
    """
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