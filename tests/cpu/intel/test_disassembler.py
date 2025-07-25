import os
import unittest
import random
from logging import getLogger, FATAL
from ptrlib.cpu import CPU
from ptrlib.cpu.intel.disassembler import IntelDisassembly

_is_windows = os.name == 'nt'

SHELLCODE_32 = (
    (0, b'j0', [], 'push', ['0x30']),
    (2, b'X', [], 'pop', ['eax']),
    (3, b'40', [], 'xor', ['al', '0x30']),
    (5, b'P', [], 'push', ['eax']),
    (6, b'P', [], 'push', ['eax']),
    (7, b'P', [], 'push', ['eax']),
    (8, b'P', [], 'push', ['eax']),
    (9, b'Q', [], 'push', ['ecx']),
    (10, b'P', [], 'push', ['eax']),
    (11, b'a', [], 'popa', []),
    (12, b'J', [], 'dec', ['edx']),
)
SHELLCODE_32_CAPSTONE = (
    (0, b'j0', [], 'push', ['0x30']),
    (2, b'X', [], 'pop', ['eax']),
    (3, b'40', [], 'xor', ['al', '0x30']),
    (5, b'P', [], 'push', ['eax']),
    (6, b'P', [], 'push', ['eax']),
    (7, b'P', [], 'push', ['eax']),
    (8, b'P', [], 'push', ['eax']),
    (9, b'Q', [], 'push', ['ecx']),
    (10, b'P', [], 'push', ['eax']),
    (11, b'a', [], 'popal', []),
    (12, b'J', [], 'dec', ['edx']),
)
SHELLCODE_32_BYTES = b'j0X40PPPPQPaJ'

SHELLCODE_64 = (
    (0, b"\x65\x48\xa1\x88\x01\x00\x00\x00\x00\x00\x00", [], 'movabs', ['rax', 'gs:0x188']),
    (11, b"\x48\x8b\x80\xb8\x00\x00\x00", [], 'mov', ['rax', 'QWORD PTR [rax+0xb8]']),
    (18, b"\x48\x89\xc1", [], 'mov', ['rcx', 'rax']),
    (21, b"\xb2\x04", [], 'mov', ['dl', '0x4']),
    (23, b"\x48\x8b\x80\xd8\x01\x00\x00", [], 'mov', ['rax', 'QWORD PTR [rax+0x1d8]']),
    (30, b"\x48\x2d\xd8\x01\x00\x00", [], 'sub', ['rax', '0x1d8']),
    (36, b"\x38\x90\xd0\x01\x00\x00", [], 'cmp', ['BYTE PTR [rax+0x1d0]', 'dl']),
    (42, b"\x75\xeb", [], 'jne', ['0x17']),
    (44, b"\x48\x8b\x90\x48\x02\x00\x00", [], 'mov', ['rdx', 'QWORD PTR [rax+0x248]']),
    (51, b"\x80\xe2\xf0", [], 'and', ['dl', '0xf0']),
    (54, b"\x48\x8b\x99\x48\x02\x00\x00", [], 'mov', ['rbx', 'QWORD PTR [rcx+0x248]']),
    (61, b"\x48\x83\xe3\x07", [], 'and', ['rbx', '0x7']),
    (65, b"\x48\x01\xda", [], 'add', ['rdx', 'rbx']),
    (68, b"\x48\x89\x91\x48\x02\x00\x00", [], 'mov', ['QWORD PTR [rcx+0x248]', 'rdx']),
    (75, b"\x65\x48\xa1\x88\x01\x00\x00\x00\x00\x00\x00", [], 'movabs', ['rax', 'gs:0x188']),
    (86, b"\x66\x8b\x88\xe4\x01\x00\x00", [], 'mov', ['cx', 'WORD PTR [rax+0x1e4]']),
    (93, b"\x66\xff\xc1", [], 'inc', ['cx']),
    (96, b"\x66\x89\x88\xe4\x01\x00\x00", [], 'mov', ['WORD PTR [rax+0x1e4]', 'cx']),
    (103, b"\x48\x8b\x90\x90\x00\x00\x00", [], 'mov', ['rdx', 'QWORD PTR [rax+0x90]']),
    (110, b"\x48\xb9\x77\x77\x77\x77\x77\x77\x77\x77", [], 'movabs', ['rcx', '0x7777777777777777']),
    (120, b"\x4c\x8b\x9a\x78\x01\x00\x00", [], 'mov', ['r11', 'QWORD PTR [rdx+0x178]']),
    (127, b"\x48\x8b\xa2\x80\x01\x00\x00", [], 'mov', ['rsp', 'QWORD PTR [rdx+0x180]']),
    (134, b"\x48\x8b\xaa\x58\x01\x00\x00", [], 'mov', ['rbp', 'QWORD PTR [rdx+0x158]']),
    (141, b"\x31\xc0", [], 'xor', ['eax', 'eax']),
    (143, b"\x0f\x01\xf8", [], 'swapgs', []),
    (146, b"\x48\x0f\x07", [], 'sysretq', [])
)
SHELLCODE_64_CAPSTONE = (
    (0, b"\x65\x48\xa1\x88\x01\x00\x00\x00\x00\x00\x00", [], 'movabs', ['rax', 'qword ptr gs:[0x188]']),
    (11, b"\x48\x8b\x80\xb8\x00\x00\x00", [], 'mov', ['rax', 'qword ptr [rax + 0xb8]']),
    (18, b"\x48\x89\xc1", [], 'mov', ['rcx', 'rax']),
    (21, b"\xb2\x04", [], 'mov', ['dl', '4']),
    (23, b"\x48\x8b\x80\xd8\x01\x00\x00", [], 'mov', ['rax', 'qword ptr [rax + 0x1d8]']),
    (30, b"\x48\x2d\xd8\x01\x00\x00", [], 'sub', ['rax', '0x1d8']),
    (36, b"\x38\x90\xd0\x01\x00\x00", [], 'cmp', ['byte ptr [rax + 0x1d0]', 'dl']),
    (42, b"\x75\xeb", [], 'jne', ['0x17']),
    (44, b"\x48\x8b\x90\x48\x02\x00\x00", [], 'mov', ['rdx', 'qword ptr [rax + 0x248]']),
    (51, b"\x80\xe2\xf0", [], 'and', ['dl', '0xf0']),
    (54, b"\x48\x8b\x99\x48\x02\x00\x00", [], 'mov', ['rbx', 'qword ptr [rcx + 0x248]']),
    (61, b"\x48\x83\xe3\x07", [], 'and', ['rbx', '7']),
    (65, b"\x48\x01\xda", [], 'add', ['rdx', 'rbx']),
    (68, b"\x48\x89\x91\x48\x02\x00\x00", [], 'mov', ['qword ptr [rcx + 0x248]', 'rdx']),
    (75, b"\x65\x48\xa1\x88\x01\x00\x00\x00\x00\x00\x00", [], 'movabs', ['rax', 'qword ptr gs:[0x188]']),
    (86, b"\x66\x8b\x88\xe4\x01\x00\x00", [], 'mov', ['cx', 'word ptr [rax + 0x1e4]']),
    (93, b"\x66\xff\xc1", [], 'inc', ['cx']),
    (96, b"\x66\x89\x88\xe4\x01\x00\x00", [], 'mov', ['word ptr [rax + 0x1e4]', 'cx']),
    (103, b"\x48\x8b\x90\x90\x00\x00\x00", [], 'mov', ['rdx', 'qword ptr [rax + 0x90]']),
    (110, b"\x48\xb9\x77\x77\x77\x77\x77\x77\x77\x77", [], 'movabs', ['rcx', '0x7777777777777777']),
    (120, b"\x4c\x8b\x9a\x78\x01\x00\x00", [], 'mov', ['r11', 'qword ptr [rdx + 0x178]']),
    (127, b"\x48\x8b\xa2\x80\x01\x00\x00", [], 'mov', ['rsp', 'qword ptr [rdx + 0x180]']),
    (134, b"\x48\x8b\xaa\x58\x01\x00\x00", [], 'mov', ['rbp', 'qword ptr [rdx + 0x158]']),
    (141, b"\x31\xc0", [], 'xor', ['eax', 'eax']),
    (143, b"\x0f\x01\xf8", [], 'swapgs', []),
    (146, b"\x48\x0f\x07", [], 'sysretq', [])
)
SHELLCODE_64_BYTES = \
    b"\x65\x48\xa1\x88\x01\x00\x00\x00\x00\x00\x00" \
    b"\x48\x8b\x80\xb8\x00\x00\x00" \
    b"\x48\x89\xc1" \
    b"\xb2\x04" \
    b"\x48\x8b\x80\xd8\x01\x00\x00" \
    b"\x48\x2d\xd8\x01\x00\x00" \
    b"\x38\x90\xd0\x01\x00\x00" \
    b"\x75\xeb" \
    b"\x48\x8b\x90\x48\x02\x00\x00" \
    b"\x80\xe2\xf0" \
    b"\x48\x8b\x99\x48\x02\x00\x00" \
    b"\x48\x83\xe3\x07" \
    b"\x48\x01\xda" \
    b"\x48\x89\x91\x48\x02\x00\x00" \
    b"\x65\x48\xa1\x88\x01\x00\x00\x00\x00\x00\x00" \
    b"\x66\x8b\x88\xe4\x01\x00\x00" \
    b"\x66\xff\xc1" \
    b"\x66\x89\x88\xe4\x01\x00\x00" \
    b"\x48\x8b\x90\x90\x00\x00\x00" \
    b"\x48\xb9\x77\x77\x77\x77\x77\x77\x77\x77" \
    b"\x4c\x8b\x9a\x78\x01\x00\x00" \
    b"\x48\x8b\xa2\x80\x01\x00\x00" \
    b"\x48\x8b\xaa\x58\x01\x00\x00" \
    b"\x31\xc0" \
    b"\x0f\x01\xf8" \
    b"\x48\x0f\x07"

class TestIntelDisassembler(unittest.TestCase):
    """Tests for Intel disassembler
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    @staticmethod
    def insn_to_tuple(insn: IntelDisassembly):
        """Convert IntelDisassembly to tuple
        """
        return (insn.address, insn.bytes, insn.prefix, insn.mnemonic, insn.operands)

    def test_32bit_objdump(self):
        """Test assembler for Intel 32-bit objdump
        """
        if _is_windows:
            return # Skip windows

        cpu = CPU('intel', 32)
        cpu.disassembler = 'objdump'

        # Test assembler
        self.assertEqual(cpu.disassemble(b''), [])
        dis = cpu.disassemble(b'\x90\xcc\x90')
        self.assertEqual(len(dis), 3)
        for i, insn in enumerate((
            (0, b'\x90', [], 'nop', []),
            (1, b'\xcc', [], 'int3', []),
            (2, b'\x90', [], 'nop', [])
        )):
            self.assertEqual(self.insn_to_tuple(dis[i]), insn)

        # Test minor assembly
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\xf3\x0f\x1e\xfa')[0]),
                         (0, b'\xf3\x0f\x1e\xfa', [], 'endbr64', []))
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\x0f\xae\xf0')[0]),
                         (0, b'\x0f\xae\xf0', [], 'mfence', []))

        # Test prefix
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\xf0\x55')[0]),
                         (0, b'\xf0\x55', ['lock'], 'push', ['ebp']))
        code = b'\x2e\x3e\x26\x36\x64\x65\x90'
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(code)[0]),
                         (0, code, ['cs', 'ds', 'es', 'ss', 'fs', 'gs'], 'nop', []))

        # Test long code and base address
        base = random.randint(0, 0xffff0000)
        dis = cpu.disassemble(SHELLCODE_32_BYTES, base)
        self.assertEqual(len(dis), len(SHELLCODE_32))
        for i, insn in enumerate(SHELLCODE_32):
            insn = (base + insn[0], insn[1], insn[2], insn[3], insn[4])
            self.assertEqual(self.insn_to_tuple(dis[i]), insn)

        # Test invalid machine code
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\x80')[0]),
                         (0, b'\x80', [], '.byte', ['0x80']))

    def test_64bit_objdump(self):
        """Test assembler for Intel 64-bit objdump
        """
        if _is_windows:
            return # Skip windows

        cpu = CPU('intel', 64)
        cpu.disassembler = 'objdump'

        # Test assembler
        self.assertEqual(cpu.disassemble(b''), [])
        dis = cpu.disassemble(b'\x90\xcc\x90')
        self.assertEqual(len(dis), 3)
        for i, insn in enumerate((
            (0, b'\x90', [], 'nop', []),
            (1, b'\xcc', [], 'int3', []),
            (2, b'\x90', [], 'nop', [])
        )):
            self.assertEqual(self.insn_to_tuple(dis[i]), insn)

        # Test minor assembly
        base = random.randint(0, 0xffff0000)
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\xf3\x0f\x1e\xfa', base)[0]),
                         (base, b'\xf3\x0f\x1e\xfa', [], 'endbr64', []))
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\x0f\xae\xf0', base)[0]),
                         (base, b'\x0f\xae\xf0', [], 'mfence', []))

        # Test prefix
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\xf0\x55')[0]),
                         (0, b'\xf0\x55', ['lock'], 'push', ['rbp']))
        code = b'\x2e\x3e\x26\x36\x64\x65\x90'
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(code)[0]),
                         (0, code, ['cs', 'ds', 'es', 'ss', 'fs', 'gs'], 'nop', []))

        # Test long code and base address
        dis = cpu.disassemble(SHELLCODE_64_BYTES)
        self.assertEqual(len(dis), len(SHELLCODE_64))
        for i, insn in enumerate(SHELLCODE_64):
            self.assertEqual(self.insn_to_tuple(dis[i]), insn)

        # Test invalid machine code
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\x80')[0]),
                         (0, b'\x80', [], '.byte', ['0x80']))

    def test_32bit_capstone(self):
        """Test assembler for Intel 32-bit capstone
        """
        cpu = CPU('intel', 32)
        cpu.disassembler = 'capstone'

        # Test assembler
        self.assertEqual(cpu.disassemble(b''), [])
        dis = cpu.disassemble(b'\x90\xcc\x90')
        self.assertEqual(len(dis), 3)
        for i, insn in enumerate((
            (0, b'\x90', [], 'nop', []),
            (1, b'\xcc', [], 'int3', []),
            (2, b'\x90', [], 'nop', [])
        )):
            self.assertEqual(self.insn_to_tuple(dis[i]), insn)

        # Test minor assembly
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\xf3\x0f\x1e\xfa')[0]),
                         (0, b'\xf3\x0f\x1e\xfa', [], 'endbr64', []))
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\x0f\xae\xf0')[0]),
                         (0, b'\x0f\xae\xf0', [], 'mfence', []))

        # Test prefix (Capstone does not support prefixes...)
        code = b'\x2e\x3e\x26\x36\x64\x65\x90'
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(code)[0]),
                         (0, code, [], 'nop', []))

        # Test long code and base address
        base = random.randint(0, 0xffff0000)
        dis = cpu.disassemble(SHELLCODE_32_BYTES, base)
        self.assertEqual(len(dis), len(SHELLCODE_32_CAPSTONE))
        for i, insn in enumerate(SHELLCODE_32_CAPSTONE):
            insn = (base + insn[0], insn[1], insn[2], insn[3], insn[4])
            self.assertEqual(self.insn_to_tuple(dis[i]), insn)

    def test_64bit_capstone(self):
        """Test assembler for Intel 64-bit capstone
        """
        cpu = CPU('intel', 64)
        cpu.disassembler = 'capstone'

        # Test assembler
        self.assertEqual(cpu.disassemble(b''), [])
        dis = cpu.disassemble(b'\x90\xcc\x90')
        self.assertEqual(len(dis), 3)
        for i, insn in enumerate((
            (0, b'\x90', [], 'nop', []),
            (1, b'\xcc', [], 'int3', []),
            (2, b'\x90', [], 'nop', [])
        )):
            self.assertEqual(self.insn_to_tuple(dis[i]), insn)

        # Test minor assembly
        base = random.randint(0, 0xffff0000)
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\xf3\x0f\x1e\xfa', base)[0]),
                         (base, b'\xf3\x0f\x1e\xfa', [], 'endbr64', []))
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(b'\x0f\xae\xf0', base)[0]),
                         (base, b'\x0f\xae\xf0', [], 'mfence', []))

        # Test prefix (Capstone does not support prefixes...)
        code = b'\x2e\x3e\x26\x36\x64\x65\x90'
        self.assertEqual(self.insn_to_tuple(cpu.disassemble(code)[0]),
                         (0, code, [], 'nop', []))

        # Test long code and base address
        dis = cpu.disassemble(SHELLCODE_64_BYTES)
        self.assertEqual(len(dis), len(SHELLCODE_64_CAPSTONE))
        for i, insn in enumerate(SHELLCODE_64_CAPSTONE):
            self.assertEqual(self.insn_to_tuple(dis[i]), insn)
