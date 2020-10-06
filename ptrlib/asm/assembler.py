import os
import subprocess
import tempfile
from logging import getLogger
from ptrlib.util.encoding import *

logger = getLogger(__name__)

def nasm(code, fmt='bin', bits=None, org=None, nasm_path=None):
    if nasm_path is None:
        try:
            nasm_path = subprocess.check_output(
                ["/usr/bin/which", "nasm"]
            ).decode().rstrip()
        except subprocess.CalledProcessError:
            raise FileNotFoundError("'nasm' not found")
            return None
    elif not os.path.isfile(nasm_path):
        raise FileNotFoundError("{}: nasm not found".format(nasm_path))

    if isinstance(code, str):
        code = str2bytes(code)

    if bits is not None:
        code = str2bytes('BITS {}\n'.format(bits)) + code
    if org is not None:
        code = str2bytes('ORG {}\n'.format(org)) + code

    with tempfile.NamedTemporaryFile() as fin:
        fin.write(code)
        fin.flush()

        with tempfile.NamedTemporaryFile() as fout:
            p = subprocess.Popen([nasm_path, "-f{}".format(fmt),
                                  fin.name, "-o", fout.name])
            if p.wait() != 0:
                logger.warn("Assemble failed")
                return None

            fout.seek(0)
            output = fout.read()

    return output

def disasm(code,
           arch='x86',
           mode='64',
           endian='little',
           address=0,
           micro=False,
           mclass=False,
           v8=False,
           v9=False,
           returns=list):
    logger.warn("`disasm` is no longer supported")
    logger.warn("Use disasm.pro instead :P")
