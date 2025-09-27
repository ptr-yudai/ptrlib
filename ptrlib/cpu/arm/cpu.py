"""This package provides the ArmCPU class.
"""
import importlib.util
from logging import getLogger
from ptrlib.types \
    import PtrlibBitsT, PtrlibAssemblerT, PtrlibDisassemblerT
from ptrlib.cpu.external import gcc, objcopy
from ptrlib.cpu.arm.assembler import assemble_gcc, assemble_keystone
from ptrlib.cpu.arm.disassembler \
    import disassemble_capstone, disassemble_objdump, ArmDisassembly
from ptrlib.cpu.arm.instructions import Instructions
from ptrlib.cpu.arm.syscall import SyscallTable

logger = getLogger(__name__)


class ArmCPU:
    """CPU and assembly features for Arm architecture.

    Examples:
        ```
        cpu = ArmCPU(32)
        code = cpu.assemble("mov r0, #0; bx lr", thumb=True)
        cpu = ArmCPU(64)
        for insn in cpu.disassemble(b'\x00\x00\x81\xe5\x00\x20\x83\xe5'):
            print(insn, insn.mnemonic, insn.operands)
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
            gcc('arm', self._bits)
            objcopy('arm', self._bits)
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
            raise NotImplementedError("NASM does not support ARM architecture.")
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
                 thumb: bool=False,
                 is_big: bool=False) -> bytes:
        """Convert assembly into machine code.

        Args:
            assembly (str): The assemble code.
            address (int): The address of the first instruction. Default to 0.
            thumb (bool): Assemble in THUMB mode. Default to False.
            is_big (bool): Assemble in big-endian mode. Default to False.

        Returns:
            bytes: The generated machine code.
        """
        if self._assembler == 'gcc':
            return assemble_gcc(assembly, self._bits, thumb, is_big)

        if self._assembler == 'keystone':
            return assemble_keystone(assembly, address, self._bits, thumb, is_big)

        raise NotImplementedError(f"Unsupported assembler: '{self._assembler}'")

    def disassemble(self,
                    bytecode: bytes,
                    address: int = 0,
                    thumb: bool = False,
                    is_big: bool = False) -> list[ArmDisassembly]:
        """Disassemble machine code into assembly.

        Args:
            bytecode (bytes): The machine code.
            address (int): The address of the first instruction. Default to 0.
            thumb (bool): Disassemble in THUMB mode. Default to False.
            is_big (bool): Disassemble in big-endian mode. Default to False.

        Returns:
            list: A list of :obj:`IntelDisassembly` objects.
        """
        if self._disassembler == 'objdump':
            return disassemble_objdump(bytecode, address, self._bits, thumb, is_big)

        if self._disassembler == 'capstone':
            return disassemble_capstone(bytecode, address, self._bits, thumb, is_big)

        raise NotImplementedError(f"Unsupported assembler: {self._disassembler}")


__all__ = ['ArmCPU']
