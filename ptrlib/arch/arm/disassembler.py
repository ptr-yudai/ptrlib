import contextlib
import os
import platform
import re
import subprocess
import tempfile
from logging import getLogger
from typing import Optional

logger = getLogger(__name__)


def disassemble_arm(code: bytes,
                    bits: int,
                    address: int,
                    thumb: bool,
                    objdump_path: Optional[str]=None) -> list:
    """Disassemble machine code to ARM assembly
    """
    from ptrlib.arch.common import which
    from .archname import is_arch_arm

    if address < 0:
        raise ValueError("VMA address must not be negative")

    if objdump_path is None:
        if is_arch_arm(platform.machine()):
            # arm --> arm: Use native compiler
            objdump_path = which('objdump')
        else:
            # not-arm --> arm: Use corss-platform compiler
            if bits == 32:
                objdump_path = which('arm-linux-gnueabihf-objdump')
                if objdump_path is None:
                    objdump_path = which('arm-linux-gnueabi-objdump')
                if objdump_path is None:
                    objdump_path = which('arm-linux-gnu-objdump')
                if objdump_path is None:
                    objdump_path = which('arm-linux-eabi-objdump')
            else:
                objdump_path = which('aarch64-linux-gnu-objdump')

    mode = 'force-thumb' if thumb else 'no-force-thumb'
    arch = 'arm' if bits == 32 else 'aarch64'

    fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.bin'
    with open(fname_bin, 'wb') as f:
        f.write(code)

    with contextlib.suppress(FileNotFoundError):
        # Disassemble
        cmd = [objdump_path,
               '-b', 'binary', '-m', arch, '-D',
               '-M', mode, f'--adjust-vma={address}',
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
        r = re.findall("([0-9a-f]+):\s+[0-9a-f]+\s+(.+)",
                       stdout.decode())
        for addr, op in r:
            op = re.sub("\s+", " ", op.strip())
            op = re.sub("//.+", "", op).strip()
            output.append((int(addr, 16), op))

        os.unlink(fname_bin)
        return output
