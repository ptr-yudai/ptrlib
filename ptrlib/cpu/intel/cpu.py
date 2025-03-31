"""This package provides the IntelCPU class.
"""
import importlib.util
from logging import getLogger
from typing import List, NamedTuple, Optional
from ptrlib.annotation import \
    PtrlibBitsT, PtrlibAssemblerT, PtrlibDisassemblerT, PtrlibAssemblySyntaxT
from ptrlib.cpu.external import gcc, objcopy
from .assembler import assemble_keystone, assemble_gcc

logger = getLogger(__name__)


class IntelInstruction(NamedTuple):
    """A single Intel instruction.

    Attributes:
        address (int): The address of this instruction.
        bytecode (bytes): The machine code bytes corresponding to this instruction.
        opcode (str): Opcode.
        operand (List[str]): Operand list.
    """
    address: int
    bytecode: bytes
    opcode: str
    operand: List[str]

class IntelCPU:
    """CPU and assembly features for Intel CPU
    """
    def __init__(self, bits: PtrlibBitsT=64):
        self._bits: PtrlibBitsT
        self._assembler: PtrlibAssemblerT
        self._disassembler: PtrlibDisassemblerT

        self._bits = bits

        # Determine assembler
        try:
            gcc('intel', self._bits)
            objcopy('intel', self._bits)
            self._assembler = 'gcc'
        except FileNotFoundError:
            if importlib.util.find_spec('keystone') is not None:
                self._assembler = 'keystone'
            else:
                self._assembler = 'none'

        # Determine disassembler
        if importlib.util.find_spec('capstone') is not None:
            self._disassembler = 'capstone'
        else:
            self._disassembler = 'none'

    @property
    def assembler(self) -> PtrlibAssemblerT:
        """Current assembler.

        This property can be either of the following values:
            - `"keystone"`: Use keystone (external library) for :obj:`assemble`.
            - `"gcc"`: Use GCC (external tool) for :obj:`assemble`.
            - `"nasm"`: Use NASM (external tool) for :obj:`assemble`.
            - `"none"`: Assembler is not available.
        """
        return self._assembler

    @assembler.setter
    def assembler(self, assembler: PtrlibAssemblerT):
        assert assembler in ('keystone', 'gcc', 'nasm'), "Invalid assembler name"
        self._assembler = assembler

    @property
    def disassembler(self) -> PtrlibDisassemblerT:
        """Current disassembler

        This property can be either of the following values:
            - `"capstone"`: Use capstone (external library) for :obj:`disassemble`.
            - `"objdump"`: Use objdump (external tool) for :obj:`disassemble`.
        """
        return self._disassembler

    def assemble(self,
                 assembly: str,
                 address: int=0,
                 syntax: Optional[PtrlibAssemblySyntaxT]=None) -> bytes:
        """Convert assembly into machine code.

        Args:
            assembly (str): The assemble code.
            address (int): The address of the first instruction. Default to 0.
            syntax (str, optional): 'intel' for Intel syntax, or 'att' for AT&T syntax.

        Returns:
            bytes: The generated machine code.
        """
        if self._assembler == 'gcc':
            logger.info("Trying to assemble using gcc...")
            return assemble_gcc(assembly, address, self._bits, syntax)

        if self._assembler == 'keystone':
            logger.info("Trying to assemble using keystone...")
            return assemble_keystone(assembly, address, self._bits, syntax)

        raise NotImplementedError(f"Unsupported assembler: '{self._assembler}'")

    def disassemble(self, bytecode: bytes) -> List[IntelInstruction]:
        """Disassemble machine code into assembly.

        Args:
            bytecode (bytes): The machine code.

        Returns:
            list: A list of :obj:`IntelInstruction` objects.
        """
        pass


__all__ = ['IntelCPU']
