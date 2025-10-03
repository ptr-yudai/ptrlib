"""This package provides assemblers for Intel architecture.
"""
import contextlib
import os
import re
import subprocess
import tempfile
from logging import getLogger
from typing import TYPE_CHECKING
from ptrlib.types import PtrlibAssemblySyntaxT, PtrlibBitsT
from ptrlib.cpu.external import gcc, objcopy, nasm

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
                      syntax: PtrlibAssemblySyntaxT | None = None) -> bytes:
    """Assemble with keystone engine.

    Args:
        assembly (str): Assembly code.
        bits (int): The bits (16, 32, or 64) for the assembly. Default to 64.
        syntax (str, optional): 'intel' for Intel syntax, or 'att' for AT&T syntax.

    Raises:
        ModuleNotFoundError: Keystone is not available.
        OSError: Assemble failed.
    """
    if not KEYSTONE_AVAILABLE:
        raise ModuleNotFoundError("Keystone is not available. "
                                  "Install it with `pip install keystone-engine`.")

    mode = {16: keystone.KS_MODE_16, 32: keystone.KS_MODE_32, 64: keystone.KS_MODE_64}
    ks = keystone.Ks(keystone.KS_ARCH_X86, mode[bits])

    if syntax is None:
        syntax = _guess_asm_syntax(assembly)

    if syntax == 'att':
        ks.syntax = keystone.KS_OPT_SYNTAX_ATT
    else:
        ks.syntax = keystone.KS_OPT_SYNTAX_INTEL

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
                 syntax: PtrlibAssemblySyntaxT | None = None) -> bytes:
    """Assemble with GCC.

    Args:
        assembly (str): Assembly code.
        bits (int): The bits (16, 32, or 64) for the assembly. Default to 64.
        syntax (str, optional): 'intel' for Intel syntax, or 'att' for AT&T syntax.

    Raises:
        FileNotFoundError: Compiler not found.
        OSError: Assemble failed.
    """
    gcc_path = gcc('intel', bits)
    objcopy_path = objcopy('intel', bits)

    assembly = '\n'.join(_normalize_assembly(assembly)[1])
    if syntax == 'att':
        assembly = '.att_syntax\n' + assembly
    else:
        assembly = '.intel_syntax noprefix\n' + assembly

    assembly = f'.code{bits}\n' + assembly

    fname_s   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.S'
    fname_o   = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.o'
    fname_bin = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.bin'
    with open(fname_s, 'w', encoding='utf-8') as f:
        f.write(assembly)

    with contextlib.suppress(FileNotFoundError), contextlib.ExitStack() as stack:
        stack.callback(os.unlink, fname_s)
        stack.callback(os.unlink, fname_o)
        stack.callback(os.unlink, fname_bin)

        # Assemble
        cmd = [gcc_path, '-nostdlib', '-c', fname_s, '-o', fname_o]
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

def assemble_nasm(assembly: str, address: int, bits: PtrlibBitsT = 64) -> bytes:
    """Assemble with NASM.

    Args:
        assembly (str): Assembly code.
        address (int): The address of the first instruction.
        bits (int): The bits (16, 32, or 64) for the assembly. Default to 64.

    Raises:
        FileNotFoundError: Compiler not found.
        OSError: Assemble failed.
    """
    nasm_path = nasm()

    # NASM does not use the 'ptr' keyword in memory operands; normalize without inserting it.
    assembly = '\n'.join(_normalize_assembly(assembly, insert_ptr=False)[1])
    assembly = f'bits {bits}\n' + assembly
    if address > 0:
        assembly = f'org {address}\n' + assembly

    fname_s = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.S'
    fname_o = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())+'.o'
    with open(fname_s, 'w', encoding='utf-8') as f:
        f.write(assembly)

    with contextlib.suppress(FileNotFoundError), contextlib.ExitStack() as stack:
        stack.callback(os.unlink, fname_s)
        stack.callback(os.unlink, fname_o)

        # Assemble
        cmd = [nasm_path, '-fbin', fname_s, '-o', fname_o]
        with subprocess.Popen(cmd, stderr=subprocess.PIPE) as p:
            if p.stderr is not None:
                for line in p.stderr.read().decode().splitlines():
                    logger.error(line)

            if p.wait() != 0:
                logger.error("Line | Code")
                logger.error("-" * 32)
                for i, line in enumerate(assembly.splitlines()):
                    logger.error("%4d | %s", i + 1, line)
                raise OSError("Assemble failed")

        with open(fname_o, 'rb') as f:
            output = f.read()
        return output

    raise OSError("Assemble failed")

def _normalize_assembly(assembly: str, insert_ptr: bool = True) -> tuple[bool, list[str]]:
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
    # Patterns for size specifier with/without 'ptr'
    re_spec_bracket = re.compile(r'\b(byte|word|dword|qword)\s*\[', re.IGNORECASE)
    re_spec_with_ptr = re.compile(r'\b(byte|word|dword|qword)\s+ptr\s*\[', re.IGNORECASE)
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
        # Handle size-specifiers around memory operands depending on assembler
        if insert_ptr:
            # GAS/Keystone style: ensure "spec ptr ["
            u = re_spec_with_ptr.sub(r'\1 ptr [', u)
            u = re_spec_bracket.sub(r'\1 ptr [', u)
        else:
            # NASM style: remove 'ptr' if present; keep "spec ["
            u = re_spec_with_ptr.sub(r'\1 [', u)
            # Do not add 'ptr' for plain "spec ["

        # Tighten brackets "[ ... ]" -> "[...]" then ensure ", [" spacing
        u = re_lbracket.sub('[', u)
        u = re_rbracket.sub(']', u)
        u = re.sub(r',\s*\[', ', [', u)

        tokens[i] = u

    return has_label, tokens

def _guess_asm_syntax(assembly: str) -> PtrlibAssemblySyntaxT:
    """Guess if the given assembly is written in Intel or AT&T syntax.

    Args:
        Assembly (str): Assembly code.

    Returns:
        str: 'intel' or 'att'
    """
    att_score = 0
    intel_score = 0

    att_score += len(re.findall(r'\$\b[0-9A-Fa-fx]+\b', assembly))
    att_score += len(re.findall(r'%[a-zA-Z][a-zA-Z0-9]*', assembly))
    att_score += len(re.findall(r'\(\s*%', assembly))
    intel_score += len(re.findall(r'\[[^\]]+\]', assembly))

    if att_score > intel_score:
        return 'att'
    return 'intel'


__all__ = ['assemble_keystone', 'assemble_gcc', 'assemble_nasm']
