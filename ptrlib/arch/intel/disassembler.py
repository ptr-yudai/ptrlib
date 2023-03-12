import contextlib
import os
import platform
import re
import subprocess
import tempfile
from logging import getLogger
from typing import Optional

logger = getLogger(__name__)


def disassemble_intel(code: bytes,
                      bits: int,
                      address: int,
                      syntax: str,
                      objdump_path: Optional[str]=None) -> list:
    """Disassemble machine code to Intel assembly
    """
    from ptrlib.arch.common import which
    from .archname import is_arch_intel

    if address < 0:
        raise ValueError("VMA address must not be negative")

    if bits == 16:
        arch = 'i8086'
    elif bits == 32:
        arch = 'i386'
    else:
        arch = 'x86-64'

    if objdump_path is None:
        if is_arch_intel(platform.machine()):
            # intel --> intel: Use native compiler
            objdump_path = which('objdump')
        else:
            # not-intel --> intel: Use corss-platform compiler
            objdump_path = which('x86_64-linux-gnu-objdump')

    fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.bin'
    with open(fname_bin, 'wb') as f:
        f.write(code)

    with contextlib.suppress(FileNotFoundError):
        # Disassemble
        cmd = [objdump_path,
               '-b', 'binary', '-m', 'i386', '-D',
               '-M', syntax, '-M', arch, f'--adjust-vma={address}',
               fname_bin]
        p = subprocess.Popen(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if p.wait() != 0:
            logger.warning("Disassemble failed")
            logger.error(stderr.decode())
            os.unlink(fname_bin)
            return

        output = []
        r = re.findall("([0-9a-f]+):\s+([0-9a-f]{2}\s)+\s+(.+)",
                       stdout.decode())
        for addr, _, op in r:
            op = re.sub("\s+", " ", op.strip())
            output.append((int(addr, 16), op))

        os.unlink(fname_bin)
        return output
