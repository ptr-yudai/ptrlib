import contextlib
import os
import subprocess
import tempfile
from logging import getLogger
from typing import Optional, Union
from ptrlib.arch.intel import assemble_intel, is_arch_intel, bit_by_arch_intel
from ptrlib.arch.arm   import assemble_arm, is_arch_arm
from ptrlib.binary.encoding import *

logger = getLogger(__name__)


def assemble(code: Union[str, bytes], bits: Optional[int]=None, arch: str='intel', syntax: str='intel', entry: Optional[str]=None,
             as_path: Optional[str]=None, ld_path: Optional[str]=None) -> Optional[bytes]:
    if isinstance(code, str):
        code = str2bytes(code)

    if code[-1] != 0x0a:
        code += b'\n'

    if entry is None:
        entry = 'ptrlib_main'
        code = b'.global ptrlib_main\nptrlib_main:\n' + code

    if is_arch_intel(arch):
        if syntax.lower() == 'intel':
            code = b'.intel_syntax noprefix\n' + code
        if bits is None:
            bits = bit_by_arch_intel(arch)
            if bits == -1: bits = 64
        return assemble_intel(code, bits, entry, as_path, ld_path)

    elif is_arch_arm(arch):
        if bits is None:
            bits = 64
        return assemble_arm(code, bits, entry, as_path, ld_path)

    else:
        raise ValueError("Unknown architecture '{}'".format(arch))


def nasm(code: Union[str, bytes], fmt: str='bin', bits: Optional[int]=None, org: Optional[int]=None, nasm_path: Optional[str]=None):
    from ptrlib.arch.common import which
    if nasm_path is None:
        nasm_path = which('nasm')

    if isinstance(code, str):
        code = str2bytes(code)

    if bits is not None:
        code = 'BITS {}\n'.format(bits).encode() + code
    if org is not None:
        code = 'ORG {}\n'.format(org).encode() + code

    fname_s = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.S'
    fname_o = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.o'
    with open(fname_s, 'wb') as f:
        f.write(code)

    with open(fname_o, 'wb+') as f, contextlib.suppress(FileNotFoundError):
        p = subprocess.Popen([nasm_path, "-f{}".format(fmt),
                              fname_s, "-o", fname_o])
        if p.wait() != 0:
            logger.warning("Assemble failed")
            os.unlink(fname_s)
            return None

        f.seek(0)
        output = f.read()

        os.unlink(fname_s)
        os.unlink(fname_o)

        return output
