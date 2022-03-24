import os
import subprocess
import tempfile
from logging import getLogger
from ptrlib.util.encoding import *

logger = getLogger(__name__)

# TODO: This should be moved to util
def which(s):
    if '/' not in s:
        try:
            s = subprocess.check_output(["which", s]).decode().rstrip()
        except subprocess.CalledProcessError:
            raise FileNotFoundError("'{}' not found".format(s))
    elif not os.path.isfile(s):
        raise FileNotFoundError("{}: File not found".format(s))
    return s

def assemble_intel(code, bits, entry):
    as_path = which('as')
    ld_path = which('ld')

    fname_s   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())
    fname_o   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())
    fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())
    with open(fname_s, 'wb') as f:
        f.write(code)

    cmd = [as_path, fname_s, '-o', fname_o]
    if bits == 32:
        cmd.append('--32')
    else:
        cmd.append('--64')

    if subprocess.Popen(cmd).wait() != 0:
        logger.warn("Assemble failed")
        try:
            os.unlink(fname_s)
        except:
            pass
        return None

    cmd = [ld_path, fname_o, '-o', fname_bin, '--oformat=binary']
    cmd.append('--entry={}'.format(entry))
    if bits == 32:
        cmd += ['-m', 'elf_i386']
    else:
        cmd += ['-m', 'elf_x86_64']

    if subprocess.Popen(cmd).wait() != 0:
        logger.warn("Linking failed")
        try:
            os.unlink(fname_s)
            os.unlink(fname_o)
        except:
            pass
        return None

    with open(fname_bin, 'rb') as f:
        output = f.read()

    try:
        os.unlink(fname_s)
        os.unlink(fname_o)
        os.unlink(fname_bin)
    except:
        pass

    return output

def assemble_arm(code, bits, entry):
    if bits == 32:
        gcc_path = which('arm-linux-gnueabi-gcc')
        objcopy_path = which('arm-linux-gnueabi-objcopy')
    else:
        gcc_path = which('aarch64-linux-gnu-gcc')
        objcopy_path = which('aarch64-linux-gnu-objcopy')

    fname_s   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex()) + '.S'
    fname_o   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())
    fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())
    with open(fname_s, 'wb') as f:
        f.write(code)

    cmd = [gcc_path, '-nostdlib', '-c', fname_s, '-o', fname_o]
    cmd.append('-Wl,--entry={}'.format(entry))

    if subprocess.Popen(cmd).wait() != 0:
        logger.warn("Assemble failed")
        try:
            os.unlink(fname_s)
        except:
            pass
        return None

    cmd = [objcopy_path, '-O', 'binary', fname_o, fname_bin]

    if subprocess.Popen(cmd).wait() != 0:
        logger.warn("Linking failed")
        try:
            os.unlink(fname_s)
            os.unlink(fname_o)
        except:
            pass
        return None

    with open(fname_bin, 'rb') as f:
        output = f.read()

    try:
        os.unlink(fname_s)
        os.unlink(fname_o)
        os.unlink(fname_bin)
    except:
        pass

    return output

def assemble(code, bits=None, arch='intel', syntax='intel', entry=None):
    arch = arch.lower()
    syntax = syntax.lower()

    if isinstance(code, str):
        code = str2bytes(code)

    if code[-1] != 0x0a:
        code += b'\n'

    if entry is None:
        entry = 'ptrlib_main'
        code = b'.global ptrlib_main\nptrlib_main:\n' + code

    if arch.startswith('arm') or arch.startswith('aarch'):
        # ARM/ARM64
        if bits is None:
            bits = 64 if '64' in arch else 32
        return assemble_arm(code, bits, entry)

    elif arch.startswith('intel') or arch.startswith('amd') or arch == 'i386'\
         or arch.startswith('x86'):
        # Intel/AMD
        if bits is None:
            bits = 64 if '64' in arch else 32

        if syntax == 'intel':
            code = b'.intel_syntax noprefix\n' + code
        return assemble_intel(code, bits, entry)

    else:
        raise ValueError("Unknown architecture '{}'".format(arch))

def nasm(code, fmt='bin', bits=None, org=None, nasm_path=None):
    if nasm_path is None:
        nasm_path = "nasm"
    nasm_path = which(nasm_path)

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
            try:
                os.unlink(fname_s)
            except:
                pass
            return None

        f.seek(0)
        output = f.read()

    try:
        os.unlink(fname_s)
        os.unlink(fname_o)
    except:
        pass

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
