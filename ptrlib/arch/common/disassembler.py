from logging import getLogger
from typing import Optional, Union
from ptrlib.arch.intel import disassemble_intel, is_arch_intel, bit_by_arch_intel
from ptrlib.arch.arm import disassemble_arm, is_arch_arm, bit_by_arch_arm
from ptrlib.binary.encoding import str2bytes

logger = getLogger(__name__)


def disassemble(code: Union[str, bytes],
                address: int=0,
                bits: Optional[int]=None,
                arch: Optional[str]='x86-64',
                syntax: Optional[str]='intel',
                thumb: Optional[bool]=False,
                returns: Optional[type]=list,
                objdump_path: str=None) -> Union[list, str]:
    if syntax.lower() == 'intel':
        syntax = 'intel' # Intel syntax
    else:
        syntax = 'att' # AT&T syntax

    if isinstance(code, str):
        code = str2bytes(code)

    if is_arch_intel(arch):
        if bits is None:
            bits = bit_by_arch_intel(arch)
            if bits == -1: bits = 64
        l = disassemble_intel(code, bits, address, syntax, objdump_path)

    elif is_arch_arm(arch):
        if bits is None:
            bits = bit_by_arch_arm(arch)
            if bits == -1: bits = 64
        l = disassemble_arm(code, bits, address, thumb, objdump_path)

    else:
        raise ValueError("Unknown architecture '{}'".format(arch))

    if returns == str:
        return '\n'.join(map(lambda v: v[1], l))
    else:
        return l

def disasm(code: Union[str, bytes],
           address: int=0,
           bits: Optional[int]=None,
           arch: Optional[str]='x86-64',
           syntax: Optional[str]='intel',
           thumb: Optional[bool]=False,
           returns: Optional[type]=list,
           objdump_path: str=None) -> Union[list, str]:
    return disassemble(code, address, bits, arch, syntax,
                       thumb, returns, objdump_path)
