import contextlib
import os
import platform
import subprocess
import tempfile
from logging import getLogger
from typing import Optional

logger = getLogger(__name__)


def assemble_arm(code: bytes, bits: int, entry: str, gcc_path: Optional[str]=None, objcopy_path: Optional[str]=None) -> Optional[bytes]:
    """Assemble code to intel machine code

    Args:
       code (bytes): Assembly code
       bits (int): Bits of architecture
       entry (str): Entry point
    """
    from ptrlib.arch.common import which
    from .archname import is_arch_arm

    if gcc_path is None or objcopy_path is None:
        if is_arch_arm(platform.machine()):
            # arm --> arm: Use native compiler
            # TODO: Handle 32/64 bits difference
            logger.warning("This feature is not fully implemented")
            gcc_path = which('gcc')
            objcopy_path = which('objcopy')
        else:
            # not-arm --> arm: Use corss-platform compiler
            if bits == 32:
                gcc_path = which('arm-linux-gnueabihf-gcc')
                objcopy_path = which('arm-linux-gnueabihf-objcopy')
                if gcc_path is None:
                    gcc_path = which('arm-linux-gnueabi-gcc')
                if gcc_path is None:
                    gcc_path = which('arm-linux-gnu-gcc')
                if gcc_path is None:
                    gcc_path = which('arm-linux-eabi-gcc')
                if objcopy_path is None:
                    objcopy_path = which('arm-linux-gnueabi-objcopy')
                if objcopy_path is None:
                    objcopy_path = which('arm-linux-gnu-objcopy')
                if objcopy_path is None:
                    objcopy_path = which('arm-linux-eabi-objcopy')
            else:
                gcc_path = which('aarch64-linux-gnu-gcc')
                objcopy_path = which('aarch64-linux-gnu-objcopy')

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
            return None

        # Extract
        cmd = [objcopy_path, '-O', 'binary', '-j', '.text', fname_o, fname_bin]
        if subprocess.Popen(cmd).wait() != 0:
            logger.warning("Extract failed")
            os.unlink(fname_s)
            os.unlink(fname_o)
            return None

        with open(fname_bin, 'rb') as f:
            output = f.read()

        os.unlink(fname_s)
        os.unlink(fname_o)
        os.unlink(fname_bin)

        return output
