"""This package provides assemblers for MIPS architecture.
"""
import contextlib
import os
import re
import subprocess
import tempfile
from logging import getLogger
from typing import TYPE_CHECKING
from ptrlib.types import PtrlibBitsT
from ptrlib.cpu.external import gcc, objcopy

try:
    import keystone
    KEYSTONE_AVAILABLE = True
except ModuleNotFoundError:
    KEYSTONE_AVAILABLE = False

if TYPE_CHECKING:
    import keystone

logger = getLogger(__name__)


def assemble_keystone(assembly: str,
                      address: int = 0,
                      bits: PtrlibBitsT = 64,
                      is_big: bool = False) -> bytes:
    """Assemble with keystone engine.

    Args:
        assembly (str): Assembly code.
        bits (int): The bits (32, or 64) for the assembly. Default to 64.
        is_big (bool): Assemble in big-endian mode. Default to False.

    Raises:
        ValueError: Invalid `bits` value.
        ModuleNotFoundError: Keystone is not available.
        OSError: Assemble failed.
    """
    if not KEYSTONE_AVAILABLE:
        raise ModuleNotFoundError("Keystone is not available. "
                                  "Install it with `pip install keystone-engine`.")
    if bits not in (32, 64):
        raise ValueError("bits must be 32 or 64")

    mode = keystone.KS_MODE_MIPS32 if bits == 32 else keystone.KS_MODE_MIPS64
    if is_big:
        mode |= keystone.KS_MODE_BIG_ENDIAN
    else:
        mode |= keystone.KS_MODE_LITTLE_ENDIAN

    ks = keystone.Ks(keystone.KS_ARCH_MIPS, mode)

    has_label, instructions = _normalize_assembly(assembly)
    if has_label:
        try:
            code, _ = ks.asm(assembly, address, True)
            if code is None:
                raise OSError("Assemble failed")
        except keystone.KsError as e:
            raise OSError(e) from e

        return bytes(code)

    # If no label exists, assemble each instruction so that we can print detailed error.
    # See: https://github.com/keystone-engine/keystone/issues/231
    code = b''
    for insn in instructions:
        try:
            insn_code, _ = ks.asm(insn, address, True)
            if insn_code is None:
                raise OSError(f"Assemble failed: {insn}")
            address += len(insn_code)
            code += bytes(insn_code)
        except keystone.KsError as e:
            raise OSError(f"Assembly failed: {insn}") from e

    return code

def assemble_gcc(assembly: str,
                 bits: PtrlibBitsT = 64,
                 is_big: bool = False) -> bytes:
    """Assemble with GCC for MIPS32/MIPS64 without trailing padding."""

    if bits not in (32, 64):
        raise ValueError("bits must be 32 or 64")

    gcc_path = gcc('mips', bits)
    objcopy_path = objcopy('mips', bits)

    assembly = '\n'.join(_normalize_assembly(assembly)[1])

    header = [
        '.section .text,"ax",@progbits',
        '.p2align 2', # 4-byte alignment at start
        '.set noreorder',
        ('.set mips32' if bits == 32 else '.set mips64'),
    ]
    assembly = '\n'.join(header) + '\n' + assembly + '\n'

    fname_s   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex()) + '.S'
    fname_o   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex()) + '.o'
    fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex()) + '.bin'
    with open(fname_s, 'w', encoding='utf-8') as f:
        f.write(assembly)

    cflags = ['-nostdlib', '-c', '-Wa,--no-pad-sections']
    if bits == 32:
        cflags += ['-mips32', '-mabi=32']
    else:
        cflags += ['-mips64', '-mabi=64']
    cflags.append('-EB' if is_big else '-EL')

    with contextlib.suppress(FileNotFoundError), contextlib.ExitStack() as stack:
        stack.callback(os.unlink, fname_s)
        stack.callback(os.unlink, fname_o)
        stack.callback(os.unlink, fname_bin)

        # Assemble
        res = subprocess.run([gcc_path, *cflags, fname_s, '-o', fname_o],
                             stderr=subprocess.PIPE, check=False)
        for line in res.stderr.decode(errors='ignore').splitlines():
            logger.error(line)
        if res.returncode != 0:
            logger.error("Line | Code")
            logger.error("-" * 32)
            for i, line in enumerate(assembly.splitlines()):
                logger.error("%4d | %s", i + 1, line)
            raise OSError("Assemble failed")

        cmd = [objcopy_path, '--dump-section', f'.text={fname_bin}', fname_o]
        with subprocess.Popen(cmd) as p:
            if p.wait() != 0:
                raise OSError("Extract failed")

        with open(fname_bin, 'rb') as f:
            return f.read()

    raise OSError("Assemble failed")

def _normalize_assembly(assembly: str) -> tuple[bool, list[str]]:
    """Normalize MIPS32/MIPS64 assembly syntax.

    - Remove comments: //, /* ... */, # (to end of line)
    - Split into one-instruction-per-token by newline and ';'
    - Whitespace normalization: collapse spaces, single space after commas
    - Tighten parentheses for MIPS addressing: "( ... )" -> "(...)", and enforce ", (" spacing

    Returns:
        (has_label: bool, tokens: list[str])
    """
    tokens: list[str] = []
    i = 0
    token = ''
    n = len(assembly)

    while i < n:
        if assembly[i:i+2] == '//':
            while i + 1 < n and assembly[i+1] != '\n':
                i += 1

        elif assembly[i:i+2] == '/*':
            while i < n and assembly[i:i+2] != '*/':
                i += 1
            i += 1  # consume '*'

        elif assembly[i] == '#':
            while i + 1 < n and assembly[i+1] != '\n':
                i += 1

        elif assembly[i] == '\n':
            if token := token.strip():
                tokens.append(token)
            token = ''

        elif assembly[i] == ';':
            if token := token.strip():
                tokens.append(token)
            token = ''

        else:
            token += assembly[i]

        i += 1

    if token := token.strip():
        tokens.append(token)

    # Normalize tokens
    has_label = False
    re_label = re.compile(r'^(?:[A-Za-z_.$][A-Za-z0-9_.$]*|\d+):')
    re_many_ws = re.compile(r'[ \t]+')
    re_comma = re.compile(r',\s*')
    re_lparen = re.compile(r'\(\s*')
    re_rparen = re.compile(r'\s*\)')

    for i, t in enumerate(tokens):
        if not has_label and re_label.match(t) is not None:
            has_label = True

        u = re_many_ws.sub(' ', t).strip()   # collapse spaces
        u = re_comma.sub(', ', u)            # "op,op" -> "op, op"
        u = re_lparen.sub('(', u)            # "(  x"  -> "(x"
        u = re_rparen.sub(')', u)            # "x  )"  -> "x)"
        u = re.sub(r',\s*\(', ', (', u)      # ",("    -> ", ("

        tokens[i] = u

    return has_label, tokens


__all__ = ['assemble_keystone', 'assemble_gcc']
