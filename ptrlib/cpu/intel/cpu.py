"""This package provides the IntelCPU class.
"""
import importlib.util
from logging import getLogger
from ptrlib.types \
    import PtrlibBitsT, PtrlibAssemblerT, PtrlibDisassemblerT, PtrlibAssemblySyntaxT
from ptrlib.cpu.external import gcc, objcopy
from ptrlib.cpu.intel.assembler import assemble_gcc, assemble_keystone, assemble_nasm
from ptrlib.cpu.intel.disassembler \
    import disassemble_capstone, disassemble_objdump, IntelDisassembly
from ptrlib.cpu.intel.instructions import Instructions
from ptrlib.cpu.intel.syscall import SyscallTable

logger = getLogger(__name__)


class IntelCPU:
    """CPU and assembly features for Intel architecture.

    Examples:
        ```
        key = b"ThisIsATestKey!!"
        cpu = IntelCPU()
        a = cpu.instruction.aesenc(b"AAAABBBBCCCCDDDD", key)
        print(cpu.instruction.aesenc_inv(a, key))

        cpu = IntelCPU(32)
        cpu.assemble(f"mov eax, {cpu.syscall.execve}")
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
        # Instructions: Emulated Intel instructions.

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
                 syntax: PtrlibAssemblySyntaxT='intel') -> bytes:
        """Convert assembly into machine code.

        Args:
            assembly (str): The assemble code.
            address (int): The address of the first instruction. Default to 0.
            syntax (str, optional): 'intel' for Intel syntax, or 'att' for AT&T syntax.

        Returns:
            bytes: The generated machine code.
        """
        if self._assembler == 'gcc':
            return assemble_gcc(assembly, self._bits, syntax)

        if self._assembler == 'keystone':
            return assemble_keystone(assembly, address, self._bits, syntax)

        if self._assembler == 'nasm':
            return assemble_nasm(assembly, address, self._bits)

        raise NotImplementedError(f"Unsupported assembler: '{self._assembler}'")

    def disassemble(self,
                    bytecode: bytes,
                    address: int=0,
                    syntax: PtrlibAssemblySyntaxT='intel') -> list[IntelDisassembly]:
        """Disassemble machine code into assembly.

        Args:
            bytecode (bytes): The machine code.
            address (int): The address of the first instruction. Default to 0.
            syntax (str, optional): 'intel' for Intel syntax, or 'att' for AT&T syntax.

        Returns:
            list: A list of :obj:`IntelDisassembly` objects.
        """
        if self._disassembler == 'objdump':
            return disassemble_objdump(bytecode, address, self._bits, syntax)

        if self._disassembler == 'capstone':
            return disassemble_capstone(bytecode, address, self._bits, syntax)

        raise NotImplementedError(f"Unsupported assembler: {self._disassembler}")


__all__ = ['IntelCPU']
