"""This package provides disassemblers for Intel architecture.
"""
import contextlib
import os
from logging import getLogger
import re
import subprocess
import tempfile
from typing import NamedTuple, TYPE_CHECKING
from ptrlib.types import PtrlibAssemblySyntaxT, PtrlibBitsT
from ptrlib.cpu.external import objdump

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ModuleNotFoundError:
    CAPSTONE_AVAILABLE = False

if TYPE_CHECKING:
    import capstone

logger = getLogger(__name__)

OBJDUMP_RE = re.compile(r'''
    ^\s*
    (?P<address>[0-9a-f]+):\s+                  # Address
    (?P<bytecode>[0-9a-f]{2}(?:\s[0-9a-f]{2})*) # Byte sequence
    (?:\s+(?P<asm>[^#\n]+))?                    # Instruction
    ''', re.IGNORECASE | re.VERBOSE)

PREFIXES = {
    'lock', 'rep', 'repe', 'repz', 'repne', 'repnz',
    'data16', 'data32', 'addr16', 'addr32',
    'cs', 'ds', 'es', 'ss', 'fs', 'gs', 'bnd',
}

class IntelDisassembly(NamedTuple):
    """A single Intel instruction.

    Attributes:
        address (int): The address of this instruction.
        bytes (bytes): The machine code bytes corresponding to this instruction.
        prefix (List[str]): Instruction prefix.
        mnemonic (str): Mnemonic.
        operands (List[str]): Operand list.
    """
    address: int
    bytes: bytes
    prefix: list[str]
    mnemonic: str
    operands: list[str]

    def __str__(self):
        return f'{self.address:08x}: ({self.bytes.hex()}) {self.mnemonic} {",".join(self.operands)}'

def disassemble_capstone(bytecode: bytes,
                         address: int=0,
                         bits: PtrlibBitsT=64,
                         syntax: PtrlibAssemblySyntaxT='intel') -> list[IntelDisassembly]:
    """Disassemble with capstone engine.

    Args:
        bytecode (bytes): The machine code.
        address (int): The address of the first instruction. Default to 0.
        bits (int): The bits (16, 32, or 64) for the assembly. Default to 64.
        syntax (str, optional): 'intel' for Intel syntax, or 'att' for AT&T syntax.

    Returns:
        list: A list of :obj:`IntelDisassembly` objects.
    """
    if not CAPSTONE_AVAILABLE:
        raise ModuleNotFoundError("Capstone is not available. "
                                  "Install it with `pip install capstone`.")

    mode = {16: capstone.CS_MODE_16, 32: capstone.CS_MODE_32, 64: capstone.CS_MODE_64}
    cs = capstone.Cs(capstone.CS_ARCH_X86, mode[bits])

    if syntax == 'att':
        cs.syntax = capstone.CS_OPT_SYNTAX_ATT
    else:
        cs.syntax = capstone.CS_OPT_SYNTAX_INTEL

    instructions: list[IntelDisassembly] = []
    for i in cs.disasm(bytecode, address):
        instructions.append(IntelDisassembly(
            address=i.address,
            bytes=bytes(i.bytes),
            prefix=[], # Capstone does not provide prefix information...
            mnemonic=i.mnemonic,
            operands=list(map(str.strip, i.op_str.split(','))) if len(i.op_str) else []
        ))

    return instructions


def disassemble_objdump(bytecode: bytes, 
                        address: int=0,
                        bits: PtrlibBitsT=64,
                        syntax: PtrlibAssemblySyntaxT='intel') -> list[IntelDisassembly]:
    """Disassemble with objdump.

    Args:
        bytecode (bytes): The machine code.
        address (int): The address of the first instruction. Default to 0.
        bits (int): The bits (16, 32, or 64) for the assembly. Default to 64.
        syntax (str, optional): 'intel' for Intel syntax, or 'att' for AT&T syntax.

    Returns:
        list: A list of :obj:`IntelDisassembly` objects.
    """
    objdump_path = objdump('intel', bits)
    arch = {16: 'i8086', 32: 'i386', 64: 'x86-64'}[bits]

    if len(bytecode) == 0:
        return []

    fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.bin'
    with open(fname_bin, 'wb') as f:
        f.write(bytecode)

    if syntax is None:
        syntax = 'intel'

    with contextlib.suppress(FileNotFoundError), \
         contextlib.ExitStack() as stack:
        stack.callback(os.unlink, fname_bin)

        # Disassemble
        cmd = [objdump_path, '-b', 'binary', '-m', 'i386', '-D',
               '-M', syntax, '-M', arch, f'--adjust-vma={address}', fname_bin]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

        if res.returncode != 0:
            logger.error(res.stderr.decode())
            raise OSError("Disassemble failed")

        # Parse the output of objdump
        instructions: list[IntelDisassembly] = []
        for line in res.stdout.decode().splitlines():
            m = OBJDUMP_RE.match(line)
            if m is None:
                continue

            if m['asm'] is None:
                # Byte sequence from previous instruction
                bytecode = instructions[-1].bytes + bytes.fromhex(m['bytecode'].replace(' ', ''))
                instructions[-1] = instructions[-1]._replace(bytes=bytecode)

            else:
                # Parse instruction
                tokens = m['asm'].split()
                prefixes = []
                while tokens and tokens[0].lower() in PREFIXES:
                    prefixes.append(tokens.pop(0).lower())

                mnemonic = tokens.pop(0)              # ここが命令本体
                operand_text = ' '.join(tokens)
                operands = [op.strip() for op in operand_text.split(',')] if operand_text else []

                instructions.append(IntelDisassembly(
                    address=int(m['address'], 16),
                    bytes=bytes.fromhex(m['bytecode'].replace(' ', '')),
                    prefix=prefixes,
                    mnemonic=mnemonic,
                    operands=operands,
                ))

        return instructions

    raise OSError("Disassemble failed")


__all__ = ['IntelDisassembly', 'disassemble_capstone', 'disassemble_objdump']
