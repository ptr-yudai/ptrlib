"""This package provides disassemblers for MIPS architecture.
"""
import contextlib
import os
from logging import getLogger
import re
import subprocess
import tempfile
from typing import NamedTuple, TYPE_CHECKING
from ptrlib.types import PtrlibBitsT
from ptrlib.cpu.external import objdump

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ModuleNotFoundError:
    CAPSTONE_AVAILABLE = False

if TYPE_CHECKING:
    import capstone

logger = getLogger(__name__)


OBJDUMP_RE = re.compile(
    r'^\s*(?P<address>[0-9a-f]+):\s+'
    r'(?P<bytecode>(?:[0-9a-f]{2}(?:\s[0-9a-f]{2})*|[0-9a-f]{8}|[0-9a-f]{4}))'
    r'(?:\s+(?P<asm>.*))?$',
    re.IGNORECASE
)

class MipsDisassembly(NamedTuple):
    """A single MIPS instruction.

    Attributes:
        address (int): The address of this instruction.
        bytes (bytes): The machine code bytes corresponding to this instruction.
        mnemonic (str): Mnemonic.
        operands (list[str]): Operand list.
    """
    address: int
    bytes: bytes
    mnemonic: str
    operands: list[str]

    def __str__(self):
        return f'{self.address:08x}: ({self.bytes.hex()}) {self.mnemonic} {",".join(self.operands)}'


def _split_operands_top_level(s: str) -> list[str]:
    """Split by commas that are not inside [], {}, or () and not inside quotes."""
    result: list[str] = []
    buf: list[str] = []
    depth_square = depth_paren = depth_brace = 0
    in_quote: str | None = None

    i = 0
    while i < len(s):
        ch = s[i]

        if in_quote:
            buf.append(ch)
            if ch == in_quote:
                in_quote = None
            i += 1
            continue
        elif ch in ("'", '"'):
            in_quote = ch
            buf.append(ch)
            i += 1
            continue

        if ch == '[':
            depth_square += 1
        elif ch == ']':
            depth_square = max(0, depth_square - 1)
        elif ch == '{':
            depth_brace += 1
        elif ch == '}':
            depth_brace = max(0, depth_brace - 1)
        elif ch == '(':
            depth_paren += 1
        elif ch == ')':
            depth_paren = max(0, depth_paren - 1)

        if ch == ',' and depth_square == 0 and depth_paren == 0 and depth_brace == 0:
            token = ''.join(buf).strip()
            if token:
                result.append(token)
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    token = ''.join(buf).strip()
    if token:
        result.append(token)
    return result

def disassemble_capstone(bytecode: bytes,
                         address: int = 0,
                         bits: PtrlibBitsT = 64,
                         is_big: bool = False) -> list[MipsDisassembly]:
    """Disassemble with capstone engine (MIPS32/MIPS64).

    Args:
        bytecode (bytes): The machine code.
        address (int): The start address of the first instruction. Default 0.
        bits (int): 32 for MIPS32, 64 for MIPS64. Default 64.
        is_big (bool): True for big-endian decoding.

    Returns:
        list[MipsDisassembly]
    """
    if not CAPSTONE_AVAILABLE:
        raise ModuleNotFoundError("Capstone is not available. "
                                  "Install it with `pip install capstone`.")

    if bits == 32:
        mode = capstone.CS_MODE_MIPS32
    elif bits == 64:
        mode = capstone.CS_MODE_MIPS64
    else:
        raise ValueError("bits must be 32 (MIPS32) or 64 (MIPS64)")

    mode |= capstone.CS_MODE_BIG_ENDIAN if is_big else capstone.CS_MODE_LITTLE_ENDIAN
    cs = capstone.Cs(capstone.CS_ARCH_MIPS, mode)

    instructions: list[MipsDisassembly] = []
    for i in cs.disasm(bytecode, address):
        op_str = i.op_str or ""
        operands = _split_operands_top_level(op_str) if op_str else []
        instructions.append(MipsDisassembly(
            address=i.address,
            bytes=bytes(i.bytes),
            mnemonic=i.mnemonic,
            operands=operands
        ))
    return instructions


def disassemble_objdump(bytecode: bytes,
                        address: int = 0,
                        bits: PtrlibBitsT = 64,
                        is_big: bool = False) -> list[MipsDisassembly]:
    """Disassemble with objdump (MIPS32/MIPS64).

    Args:
        bytecode (bytes): The machine code.
        address (int): The start address of the first instruction. Default 0.
        bits (int): 32 for MIPS32, 64 for MIPS64. Default 64.
        is_big (bool): True for big-endian decoding.

    Returns:
        list[MipsDisassembly]
    """
    objdump_path = objdump('mips', bits)
    if bits not in (32, 64):
        raise ValueError("bits must be 32 (MIPS32) or 64 (MIPS64)")

    if len(bytecode) == 0:
        return []

    fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex()) + '.bin'
    with open(fname_bin, 'wb') as f:
        f.write(bytecode)

    with contextlib.suppress(FileNotFoundError), contextlib.ExitStack() as stack:
        stack.callback(os.unlink, fname_bin)

        # Disassemble
        cmd = [objdump_path, '-b', 'binary', '-m', 'mips', '-D',
               ('-EB' if is_big else '-EL'),
               '-M', ('mips64' if bits == 64 else 'mips32'),
               f'--adjust-vma={address}',
               fname_bin]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

        if res.returncode != 0:
            logger.error(res.stderr.decode(errors='ignore'))
            raise OSError("Disassemble failed")

        instructions: list[MipsDisassembly] = []
        for line in res.stdout.decode(errors='ignore').splitlines():
            m = OBJDUMP_RE.match(line)
            if m is None:
                continue

            bc_hex = m['bytecode'].replace(' ', '')
            if m['asm'] is None or not m['asm'].strip():
                if not instructions:
                    continue
                new_bytes = instructions[-1].bytes + bytes.fromhex(bc_hex)
                instructions[-1] = instructions[-1]._replace(bytes=new_bytes)
                continue

            asm_text = m['asm'].strip()
            parts = asm_text.split(None, 1)
            mnemonic = parts[0]
            operand_text = parts[1] if len(parts) > 1 else ''
            operands = _split_operands_top_level(operand_text) if operand_text else []

            instructions.append(MipsDisassembly(
                address=int(m['address'], 16),
                bytes=bytes.fromhex(bc_hex),
                mnemonic=mnemonic,
                operands=operands,
            ))

        return instructions

    raise OSError("Disassemble failed")


__all__ = ['MipsDisassembly', 'disassemble_capstone', 'disassemble_objdump']
