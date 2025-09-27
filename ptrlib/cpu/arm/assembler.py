"""This package provides assemblers for Arm architecture.
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
                      thumb: bool = False,
                      is_big: bool = False) -> bytes:
    """Assemble with keystone engine.

    Args:
        assembly (str): Assembly code.
        bits (int): 32 for ARM/Thumb, 64 for AArch64. Default to 64.
        thumb (bool): Assemble in THUMB mode. Default to False.
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
        raise ValueError("`bits` must be either 32 or 64")

    arch = keystone.KS_ARCH_ARM if bits == 32 else keystone.KS_ARCH_ARM64
    mode = keystone.KS_MODE_ARM if thumb is False else keystone.KS_MODE_THUMB
    if is_big:
        mode |= keystone.KS_MODE_BIG_ENDIAN
    else:
        mode |= keystone.KS_MODE_LITTLE_ENDIAN

    ks = keystone.Ks(arch, mode)

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
                 thumb: bool = False,
                 is_big: bool = False) -> bytes:
    """Assemble with GCC.

    Args:
        assembly (str): Assembly code.
        bits (int): 32 for ARM/Thumb, 64 for AArch64. Default to 64.
        thumb (bool): Assemble in THUMB mode. Default to False.
        is_big (bool): Assemble in big-endian mode. Default to False.

    Raises:
        ValueError: Invalid `bits` value.
        FileNotFoundError: Compiler not found.
        OSError: Assemble failed.
    """
    if bits not in (32, 64):
        raise ValueError("`bits` must be either 32 or 64")

    gcc_path = gcc('arm', bits)
    objcopy_path = objcopy('arm', bits)

    assembly = '\n'.join(_normalize_assembly(assembly)[1])
    header = ['.text']
    if bits == 32:
        header.append('.thumb' if thumb else '.arm')
    assembly = '\n'.join(header) + '\n' + assembly

    fname_s   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.S'
    fname_o   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.o'
    fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.bin'
    with open(fname_s, 'w', encoding='utf-8') as f:
        f.write(assembly)

    cflags = ['-nostdlib', '-c']
    if bits == 32:
        cflags.append('-mthumb' if thumb else '-marm')
    cflags.append('-mbig-endian' if is_big else '-mlittle-endian')

    with contextlib.suppress(FileNotFoundError), \
         contextlib.ExitStack() as stack:
        stack.callback(os.unlink, fname_s)
        stack.callback(os.unlink, fname_o)
        stack.callback(os.unlink, fname_bin)

        # Assemble
        cmd = [gcc_path, *cflags, fname_s, '-o', fname_o]
        res = subprocess.run(cmd, stderr=subprocess.PIPE, check=False)

        for line in res.stderr.decode().splitlines():
            logger.error(line)

        if res.returncode != 0:
            logger.error("Line | Code")
            logger.error("-" * 32)
            for i, line in enumerate(assembly.splitlines()):
                logger.error("%4d | %s", i + 1, line)
            raise OSError("Assemble failed")

        # Extract
        cmd = [objcopy_path, '-O', 'binary', '-j', '.text', fname_o, fname_bin]
        with subprocess.Popen(cmd) as p:
            if p.wait() != 0:
                raise OSError("Extract failed")

        with open(fname_bin, 'rb') as f:
            return f.read()

    raise OSError("Assemble failed")

def _normalize_assembly(assembly: str) -> tuple[bool, list[str]]:
    """Normalize assembly syntax.

    Args:
        Assembly (str): Assembly code

    Returns:
        tuple: First: True if the code has labels, otherwise false.
               Second: A list of normalized assembly instructions.
    """
    # Split into instructions
    tokens = []
    i = 0
    token = ''
    while i < len(assembly):
        if assembly[i:i+2] == '//':
            while i+1 < len(assembly) and assembly[i+1] != '\n':
                i += 1

        elif assembly[i:i+2] == '/*':
            while i < len(assembly) and assembly[i:i+2] != '*/':
                i += 1
            i += 1

        elif assembly[i] == '@' and (i == 0 or assembly[i-1].isspace()):
            while i+1 < len(assembly) and assembly[i+1] != '\n':
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

    # Normalize syntax
    has_label = False
    re_label = re.compile(r'^[a-zA-Z0-9_.]+:')
    re_many_ws = re.compile(r'[ \t]+')
    re_comma = re.compile(r',\s*')
    re_lbracket = re.compile(r'\[\s*')
    re_rbracket = re.compile(r'\s*\]')
    for i, token in enumerate(tokens):
        if not has_label and re_label.match(token) is not None:
            has_label = True

        # Collapse excessive spaces
        u = re_many_ws.sub(' ', token).strip()
        # Ensure single space after commas
        u = re_comma.sub(', ', u)
        # Tighten brackets "[ ... ]" -> "[...]" then ensure ", [" spacing
        u = re_lbracket.sub('[', u)
        u = re_rbracket.sub(']', u)
        u = re.sub(r',\s*\[', ', [', u)

        tokens[i] = u

    return has_label, tokens


__all__ = ['assemble_keystone', 'assemble_gcc']
