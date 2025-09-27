"""This package provides the ArmCPU class.
"""
import importlib.util
from logging import getLogger
from ptrlib.types \
    import PtrlibBitsT, PtrlibAssemblerT, PtrlibDisassemblerT
from ptrlib.cpu.external import gcc, objcopy
from ptrlib.cpu.mips.assembler import assemble_gcc, assemble_keystone
from ptrlib.cpu.mips.disassembler \
    import disassemble_capstone, disassemble_objdump, MipsDisassembly
from ptrlib.cpu.mips.instructions import Instructions
from ptrlib.cpu.mips.syscall import SyscallTable

logger = getLogger(__name__)


class MipsCPU:
    """CPU and assembly features for MIPS architecture.

    Examples:
        ```
        ```
    """
    def __init__(self, bits: PtrlibBitsT=64):
        self._bits: PtrlibBitsT = bits
        self._assembler: PtrlibAssemblerT
        self._disassembler: PtrlibDisassemblerT

        # TODO: Do not create an instance here
        self.syscall = SyscallTable(bits)
        # SyscallTable: System call table.
        self.instruction = Instructions()
        # Instructions: Emulated MIPS instructions.

        # Determine assembler
        try:
            gcc('mips', self._bits)
            objcopy('mips', self._bits)
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
            - `"none"`: Assembler is not available.
        """
        return self._assembler

    @assembler.setter
    def assembler(self, assembler: PtrlibAssemblerT):
        assert assembler in ('keystone', 'gcc', 'nasm'), "Invalid assembler name"
        if assembler == 'nasm':
            raise NotImplementedError("NASM does not support MIPS architecture.")
        self._assembler = assembler

    @property
    def disassembler(self) -> PtrlibDisassemblerT:
        """Current disassembler

        This property can be either of the following values:
            - `"capstone"`: Use capstone (external library) for :obj:`disassemble`.
            - `"objdump"`: Use objdump (external tool) for :obj:`disassemble`.
            - `"none"`: Disassembler is not available.
        """
        return self._disassembler

    @disassembler.setter
    def disassembler(self, disassembler: PtrlibDisassemblerT):
        assert disassembler in ('capstone', 'objdump'), "Invalid disassembler name"
        self._disassembler = disassembler

    def assemble(self,
                 assembly: str,
                 address: int=0,
                 is_big: bool=False) -> bytes:
        """Convert assembly into machine code.

        Args:
            assembly (str): The assemble code.
            address (int): The address of the first instruction. Default to 0.
            is_big (bool): Assemble in big-endian mode. Default to False.

        Returns:
            bytes: The generated machine code.
        """
        if self._assembler == 'gcc':
            return assemble_gcc(assembly, self._bits, is_big)

        if self._assembler == 'keystone':
            return assemble_keystone(assembly, address, self._bits, is_big)

        raise NotImplementedError(f"Unsupported assembler: '{self._assembler}'")

    def disassemble(self,
                    bytecode: bytes,
                    address: int = 0,
                    is_big: bool = False) -> list[MipsDisassembly]:
        """Disassemble machine code into assembly.

        Args:
            bytecode (bytes): The machine code.
            address (int): The address of the first instruction. Default to 0.
            is_big (bool): Disassemble in big-endian mode. Default to False.

        Returns:
            list: A list of :obj:`MipsDisassembly` objects.
        """
        if self._disassembler == 'objdump':
            return disassemble_objdump(bytecode, address, self._bits, is_big)

        if self._disassembler == 'capstone':
            return disassemble_capstone(bytecode, address, self._bits, is_big)

        raise NotImplementedError(f"Unsupported assembler: {self._disassembler}")


__all__ = ['MipsCPU']
