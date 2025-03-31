"""This package provides assemblers for Intel architecture.
"""
import contextlib
import os
import re
import subprocess
import tempfile
from logging import getLogger
from typing import List, Optional, Tuple, TYPE_CHECKING
from ptrlib.annotation import PtrlibAssemblySyntaxT, PtrlibBitsT
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
                      address: int=0,
                      bits: PtrlibBitsT=64,
                      syntax: Optional[PtrlibAssemblySyntaxT]=None) -> bytes:
    """Assemble with keystone engine.

    Args:
        assembly (str): Assembly code.
        address (int): The address of the first instruction.
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
        syntax = guess_asm_syntax(assembly)

    if syntax == 'att':
        ks.syntax = keystone.KS_OPT_SYNTAX_ATT
    else:
        ks.syntax = keystone.KS_OPT_SYNTAX_INTEL

    has_label, instructions = normalize_assembly(assembly)
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
                address: int=0,
                bits: PtrlibBitsT=64,
                syntax: Optional[PtrlibAssemblySyntaxT]=None) -> bytes:
    """Assemble with GCC.

    Args:
        assembly (str): Assembly code.
        address (int): The address of the first instruction.
        bits (int): The bits (16, 32, or 64) for the assembly. Default to 64.
        syntax (str, optional): 'intel' for Intel syntax, or 'att' for AT&T syntax.

    Raises:
        FileNotFoundError: Compiler not found.
        OSError: Assemble failed.
    """
    gcc_path = gcc('intel', bits)
    objcopy_path = objcopy('intel', bits)

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

    with contextlib.suppress(FileNotFoundError), \
         contextlib.ExitStack() as stack:
        stack.callback(os.unlink, fname_s)
        stack.callback(os.unlink, fname_o)
        stack.callback(os.unlink, fname_bin)

        # Assemble
        cmd = [gcc_path, '-nostdlib', '-c', fname_s, '-o', fname_o]
        with subprocess.Popen(cmd) as p:
            if p.wait() != 0:
                raise OSError("Assemble failed")

        # Extract
        cmd = [objcopy_path, '-O', 'binary', '-j', '.text', fname_o, fname_bin]
        with subprocess.Popen(cmd) as p:
            if p.wait() != 0:
                raise OSError("Extract failed")

        with open(fname_bin, 'rb') as f:
            output = f.read()

        return output

def assemble_nasm(assembly: str):
    pass

def normalize_assembly(assembly: str) -> Tuple[bool, List[str]]:
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
            while i < len(assembly) and assembly[i] != '\n':
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
    re_label = re.compile(r'^[a-zA-Z0-9_]+:')
    re_spec = re.compile(r'(byte|word|dword|qword)\s*\[', re.IGNORECASE)

    for i, token in enumerate(tokens):
        if not has_label and re_label.match(token) is not None:
            has_label = True

        tokens[i] = re_spec.sub(r'\1 ptr \[', token)

    return has_label, tokens

def guess_asm_syntax(assembly: str) -> PtrlibAssemblySyntaxT:
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
