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
                ["which", "nasm"]
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

    fname_s = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())
    fname_o = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())
    with open(fname_s, 'wb') as f:
        f.write(code)

    with open(fname_o, 'wb+') as f:
        p = subprocess.Popen([nasm_path, "-f{}".format(fmt),
                              fname_s, "-o", fname_o])
        if p.wait() != 0:
            logger.warn("Assemble failed")
            return None

        f.seek(0)
        output = f.read()

    try:
        os.unlink(fname_s)
    except:
        logger.warn("Could not delete temporary file: {}".format(fname_s))
    try:
        os.unlink(fname_o)
    except:
        logger.warn("Could not delete temporary file: {}".format(fname_s))

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
