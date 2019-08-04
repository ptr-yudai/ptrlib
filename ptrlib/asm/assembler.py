from logging import getLogger
from capstone import *
try:
    from keystone import *
except ModuleNotFoundError:
    keystone = None
from ptrlib.util.encoding import str2bytes

logger = getLogger(__name__)

def asm(code,
        arch='x86',
        mode='64',
        syntax='radix16',
        endian='little'):
    """ Assemble into machine code
    
    Assemble given code to machine code on specified architecture.

    Args:
    
    
    Returns:
        bytes: Machine code
    """
    if keystone is None:
        logger.warn("'keystone' is not installed!")
        print(" | You have to compile & install keystone")
        print(" | After that, run `pip install keystone-engine`")
        print(" | See the following link for how to compile keystone")
        print(" | http://www.keystone-engine.org/docs/")
        return None
    
    arch = arch.lower()
    mode = mode.lower()
    syntax = syntax.lower()

    # mode
    if   mode == '16'      : m = KS_MODE_16
    elif mode == '32'      : m = KS_MODE_32
    elif mode == '64'      : m = KS_MODE_64
    elif mode == 'arm'     : m = KS_MODE_ARM
    elif mode == 'thumb'   : m = KS_MODE_THUMB
    elif mode == 'mips32'  : m = KS_MODE_MIPS32
    elif mode == 'mips64'  : m = KS_MODE_MIPS64
    elif mode == 'ppc32'   : m = KS_MODE_PPC32
    elif mode == 'ppc64'   : m = KS_MODE_PPC64
    elif mode == 'sparc32' : m = KS_MODE_SPARC32
    else:
        logger.warn("Invalid mode specified")
        return None

    # arch
    if   arch == 'x86': a = KS_ARCH_X86
    elif arch == 'arm': a = KS_ARCH_ARM
    elif arch == 'arm64': a = KS_ARCH_ARM64
    elif arch == 'hexagon': a = KS_ARCH_HEXAGON
    elif arch == 'MIPS': a = KS_ARCH_MIPS
    elif arch == 'PPC': a = KS_ARCH_PPC
    elif arch == 'sparc': a = KS_ARCH_SPARC
    elif arch == 'sysz': a = KS_ARCH_SYSTEMZ

    # syntax
    if   syntax == 'radix16': s = KS_OPT_SYNTAX_RADIX16
    elif syntax == 'att': s = KS_OPT_SYNTAX_ATT
    elif syntax == 'radix16att': s = KS_OPT_SYNTAX_ATT + KS_OPT_SYNTAX_RADIX16
    
    # Check mode
    if a == KS_ARCH_X86:
        if m not in [KS_MODE_16, KS_MODE_32, KS_MODE_64]:
            logger.error("'16','32','64' can be used with arch=``".format(arch))
    elif a == KS_ARCH_PPC:
        if m not in [KS_MODE_PPC32, KS_MODE_PPC64]:
            logger.error("'ppc32','ppc64' can be used with arch=``".format(arch))
    elif a == KS_ARCH_MIPS:
        if m not in [KS_MODE_MIPS32, KS_MODE_MIPS64]:
            logger.error("'mips32','mips64' can be used with arch=``".format(arch))
    elif a == KS_ARCH_SPARC:
        if m != KS_MODE_SPARC32:
            logger.error("'sparc32' can be used with arch=``".format(arch))
    elif a == KS_ARCH_ARM64:
        if m != KS_MODE_ARM:
            logger.error("'arm' can be used with arch=``".format(arch))
    elif a == KS_ARCH_ARM:
        if m not in [KS_MODE_ARM, KS_MODE_THUMB]:
            logger.error("'arm','thumb' can be used with arch=``".format(arch))

    if endian == 'little':
        m += KS_MODE_LITTLE_ENDIAN
    elif endian == 'big':
        m += KS_MODE_BIG_ENDIAN
    else:
        logger.error("Invalid endian specified")

    if a in [KS_ARCH_HEXAGON, KS_ARCH_SYSZ]: m = 0
    
    ks = Ks(a, m)
    encoding, _ = ks.asm(code)
    return encoding

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
    """Disassemble machine code
    
    Disassemble machine code on specified architecture.

    Args:
        code (byte)   : Target machine code
        arch (str)    : Architecture (x86, arm, arm64, mips, ppc, sparc, sysz, xcore)
        mode (str)    : Basic mode (16, 32, 64, mips32, mips64, mips32r6, arm, thumb)
        endian (str)  : Endian ('little' / 'big')
        address (int) : Base address
        micro (bool)  : Use CS_MODE_MICRO
        mclass (bool) : Use CS_MODE_MCLASS
        v8 (bool)     : Use CS_MODE_V8
        v9 (bool)     : Use CS_MODE_V9
        returns (bool): Result format (list / str)
    
    Returns:
        list: Assembly list
    """
    if isinstance(code, str): code = str2bytes(code)
    arch = arch.lower()
    mode = mode.lower()
    
    # mode
    if   mode == '16'       : m = CS_MODE_16
    elif mode == '32'       : m = CS_MODE_32
    elif mode == '64'       : m = CS_MODE_64
    elif mode == 'mips32'   : m = CS_MODE_MIPS32
    elif mode == 'mips64'   : m = CS_MODE_MIPS64
    elif mode == 'mips32r6' : m = CS_MODE_MIPS32R6
    elif mode == 'arm'      : m = CS_MODE_ARM
    elif mode == 'thumb'    : m = CS_MODE_THUMG
    else:
        logger.warn("`{}`: No such mode".format(mode))
        return None
    
    # arch
    if   arch == 'arm'   : a = CS_ARCH_ARM
    elif arch == 'arm64' : a = CS_ARCH_ARM64
    elif arch == 'mips'  : a = CS_ARCH_MIPS
    elif arch == 'ppc'   : a = CS_ARCH_PPC
    elif arch == 'sparc' : a = CS_ARCH_SPARC
    elif arch == 'sysz'  : a = CS_ARCH_SYSZ
    elif arch == 'x86'   : a = CS_ARCH_X86
    elif arch == 'xcore' : a = CS_ARCH_XCORE
    else:
        logger.warn("`{}`: No such architecture".format(arch))
        return None

    # Check mode
    if a == CS_ARCH_X86:
        if m not in [CS_MODE_16, CS_MODE_32, CS_MODE_64]:
            logger.error("'16','32','64' can be used with arch=``".format(arch))
    elif a == CS_ARCH_PPC:
        if m not in [CS_MODE_32, CS_MODE_64]:
            logger.error("'32','64' can be used with arch=``".format(arch))
    elif a == CS_ARCH_MIPS:
        if m not in [CS_MODE_MIPS32, CS_MODE_MIPS64, CS_MODE_MIPS32R6]:
            logger.error("'mips32','mips64','mips32r6' can be used with arch=``".format(arch))
    elif a == CS_ARCH_ARM64:
        if m != CS_MODE_ARM:
            logger.error("'arm' can be used with arch=``".format(arch))
    elif a == CS_ARCH_ARM:
        if m not in [CS_MODE_ARM, CS_MODE_THUMB]:
            logger.error("'arm','thumb' can be used with arch=``".format(arch))

    if endian == 'little':
        m += CS_MODE_LITTLE_ENDIAN
    elif endian == 'big':
        m += CS_MODE_BIG_ENDIAN
    else:
        logger.error("Invalid endian specified")

    if micro: m += CS_MODE_MICRO
    if mclass: m += CS_MODE_MCLASS
    if v8: m += CS_MODE_V8
    if v9 and endian == 'big': m += CS_MODE_V9

    if a in [CS_ARCH_SPARC, CS_ARCH_SYSZ, CS_ARCH_XCORE]: m = 0
    
    md = Cs(a, m)
    if returns == str:
        result = ''
        for i in md.disasm(code, address):
            result += "{:x}:\t{}\t{}".format(i.address, i.mnemonic, i.op_str)
    else:
        result = []
        for i in md.disasm(code, address):
            result.append((i.address, i.mnemonic, i.op_str))

    return result

if __name__ == '__main__':
    x = disasm("\x00\x01\x02\x03", arch='arm', mode='arm')
    print(x)
    y = asm(x, arch='arm', mode='arm')
    print(y)
