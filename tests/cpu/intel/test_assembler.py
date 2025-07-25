import os
import unittest
from logging import getLogger, FATAL
from ptrlib.cpu import CPU

_is_windows = os.name == 'nt'

# TODO: Test AT&T syntax

CONST_GCC = '.byte 0; .word 1; .long 2; .quad 3; .asciz "/bin/sh"; .ascii "/bin/sh"'
CONST_GCC_BYTES = \
    b'\x00\x01\x00\x02\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00' \
    b'/bin/sh\0/bin/sh'

CONST_NASM = 'db 0; dw 1; dd 2; dq 3; db "/bin/sh", 0; db "/bin/sh"'
CONST_NASM_BYTES = \
    b'\x00\x01\x00\x02\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00' \
    b'/bin/sh\0/bin/sh'

SHELLCODE_32 = """
    push 0x30
    pop eax
    xor al, 0x30 // omit eax, ecx
    push eax  /* edx = 0 */
    push eax  /* ebx = 0 */
    push eax
    push eax
    push ecx  /* esi = buffer */
    push eax
    popad
    dec edx   /* edx = 0xffffffff */
"""
SHELLCODE_32_BYTES = b'j0X40PPPPQPaJ'

SHELLCODE_64 = """
    movabs rax, qword ptr gs:[0x188]    // Prcb.CurrentThread
    mov rax, qword ptr [rax + 0xb8]     // ApcState.Process
    mov rcx, rax
    mov dl, 4
FindSystemProcess:
    mov rax, qword ptr [rax + 0x1d8]    // Eprocess.ActiveProcessLinks
    sub rax, 0x1d8
    cmp byte ptr [rax + 0x1d0], dl      // UniqueProcessId
    jne FindSystemProcess

    /* Steal token */
    mov rdx, qword ptr [rax + 0x248]
    and dl, 0xf0
    mov rbx, qword ptr [rcx + 0x248]
    and rbx, 7
    add rdx, rbx
    mov qword ptr [rcx + 0x248], rdx

    /* Retrun to usermode
    The constant 0x7777...7777 should be replaced */
    movabs rax, qword ptr gs:[0x188]
    mov cx, word ptr [rax + 0x1e4]
    inc cx
    mov word ptr [rax + 0x1e4], cx
    mov rdx, qword ptr [rax + 0x90]
    mov rcx, 0x7777777777777777
    mov r11, qword ptr [rdx + 0x178]
    mov rsp, qword ptr [rdx + 0x180]
    mov rbp, qword ptr [rdx + 0x158]
    xor eax, eax
    swapgs
    sysretq
"""
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

class TestIntelAssembler(unittest.TestCase):
    """Test Intel assembler
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_32bit_gcc(self):
        """Test assembler for Intel 32-bit GCC
        """
        if _is_windows:
            return # Skip windows

        cpu = CPU('intel', 32)
        cpu.assembler = 'gcc'

        # Test assembler
        self.assertEqual(cpu.assemble(''), b'')
        self.assertEqual(cpu.assemble('nop'), b'\x90')
        self.assertEqual(cpu.assemble('nop; nop'), b'\x90\x90')
        self.assertEqual(cpu.assemble('a:nop\nb:int3;nop'), b'\x90\xcc\x90')

        # Test minor assembly
        self.assertEqual(cpu.assemble('endbr64'), b'\xf3\x0f\x1e\xfa')
        self.assertEqual(cpu.assemble('lgdtd [edi]; lgdtw [edi]'), b'\x0f\x01\x17f\x0f\x01\x17')
        self.assertEqual(cpu.assemble('mfence; sfence; lfence'),
                         b'\x0f\xae\xf0\x0f\xae\xf8\x0f\xae\xe8')
        self.assertEqual(cpu.assemble('A: /* infinite call */ call A'), b'\xe8\xfb\xff\xff\xff')
        self.assertEqual(cpu.assemble('call far [esp]'), b'\xff\x94$\x06\xff\x00\x00')

        # Test long code
        self.assertEqual(cpu.assemble(SHELLCODE_32), SHELLCODE_32_BYTES)

        # Test constant
        self.assertEqual(cpu.assemble(CONST_GCC), CONST_GCC_BYTES)

        # Test exception
        with self.assertRaises(OSError):
            cpu.assemble("invalid_insn eax, eax")
        with self.assertRaises(OSError):
            cpu.assemble("add eax, bx")

    def test_64bit_gcc(self):
        """Test assembler for Intel 64-bit GCC
        """
        if _is_windows:
            return # Skip windows

        cpu = CPU('intel', 64)
        cpu.assembler = 'gcc'

        # Test assembler
        self.assertEqual(cpu.assemble(''), b'')
        self.assertEqual(cpu.assemble('nop'), b'\x90')
        self.assertEqual(cpu.assemble('nop; nop'), b'\x90\x90')
        self.assertEqual(cpu.assemble('a:nop\nb:int3;nop'), b'\x90\xcc\x90')

        # Test minor assembly
        self.assertEqual(cpu.assemble('endbr64'), b'\xf3\x0f\x1e\xfa')
        self.assertEqual(cpu.assemble('lgdt [rdi]'), b'\x0f\x01\x17')
        self.assertEqual(cpu.assemble('mfence; sfence; lfence'),
                         b'\x0f\xae\xf0\x0f\xae\xf8\x0f\xae\xe8')
        self.assertEqual(cpu.assemble('A: /* infinite call */ call A'), b'\xe8\xfb\xff\xff\xff')
        self.assertEqual(cpu.assemble('call far [rsp]'), b'\xff\x94$\x06\xff\x00\x00')

        # Test long code
        self.assertEqual(cpu.assemble(SHELLCODE_64), SHELLCODE_64_BYTES)

        # Test constant
        self.assertEqual(cpu.assemble(CONST_GCC), CONST_GCC_BYTES)

        # Test exception
        with self.assertRaises(OSError):
            cpu.assemble("invalid_insn eax, eax")
        with self.assertRaises(OSError):
            cpu.assemble("add rax, ebx")

    def test_32bit_keystone(self):
        """Test assembler for Intel 32-bit keystone
        """
        cpu = CPU('intel', 32)
        cpu.assembler = 'keystone'

        # Test assembler
        self.assertEqual(cpu.assemble(''), b'')
        self.assertEqual(cpu.assemble('nop'), b'\x90')
        self.assertEqual(cpu.assemble('nop; nop'), b'\x90\x90')
        self.assertEqual(cpu.assemble('a:nop\nb:int3;nop'), b'\x90\xcc\x90')

        # Test minor assembly
        with self.assertRaises(OSError):
            cpu.assemble('endbr64') # keystone is too out-dated...
        self.assertEqual(cpu.assemble('mfence; sfence; lfence'),
                         b'\x0f\xae\xf0\x0f\xae\xf8\x0f\xae\xe8')
        self.assertEqual(cpu.assemble('A: /* infinite call */ call A'), b'\xe8\xfb\xff\xff\xff')

        # Test long code
        self.assertEqual(cpu.assemble(SHELLCODE_32), SHELLCODE_32_BYTES)

        # Test constant
        self.assertEqual(cpu.assemble(CONST_GCC), CONST_GCC_BYTES)

        # Test exception
        with self.assertRaises(OSError):
            cpu.assemble("invalid_insn eax, eax")
        with self.assertRaises(OSError):
            cpu.assemble("add eax, bx")

    def test_64bit_keystone(self):
        """Test assembler for Intel 64-bit keystone
        """
        cpu = CPU('intel', 64)
        cpu.assembler = 'keystone'

        # Test assembler
        self.assertEqual(cpu.assemble(''), b'')
        self.assertEqual(cpu.assemble('nop'), b'\x90')
        self.assertEqual(cpu.assemble('nop; nop'), b'\x90\x90')
        self.assertEqual(cpu.assemble('a:nop\nb:int3;nop'), b'\x90\xcc\x90')

        # Test minor assembly
        with self.assertRaises(OSError):
            cpu.assemble('endbr64') # keystone is too out-dated...
        self.assertEqual(cpu.assemble('lgdt [rdi]'), b'\x0f\x01\x17')
        self.assertEqual(cpu.assemble('mfence; sfence; lfence'),
                         b'\x0f\xae\xf0\x0f\xae\xf8\x0f\xae\xe8')
        self.assertEqual(cpu.assemble('A: /* infinite call */ call A'), b'\xe8\xfb\xff\xff\xff')

        # Test constant
        self.assertEqual(cpu.assemble(CONST_GCC), CONST_GCC_BYTES)

        # Test exception
        with self.assertRaises(OSError):
            cpu.assemble("invalid_insn eax, eax")
        with self.assertRaises(OSError):
            cpu.assemble("add rax, ebx")

    def test_32bit_nasm(self):
        """Test assembler for Intel 32-bit nasm
        """
        if _is_windows:
            return # Skip windows

        cpu = CPU('intel', 32)
        cpu.assembler = 'nasm'

        # Test assembler
        self.assertEqual(cpu.assemble(''), b'')
        self.assertEqual(cpu.assemble('nop'), b'\x90')
        self.assertEqual(cpu.assemble('nop; nop'), b'\x90\x90')
        self.assertEqual(cpu.assemble('a:nop\nb:int3;nop'), b'\x90\xcc\x90')

        # Test minor assembly
        self.assertEqual(cpu.assemble('endbr64'), b'\xf3\x0f\x1e\xfa')
        self.assertEqual(cpu.assemble('mfence; sfence; lfence'),
                         b'\x0f\xae\xf0\x0f\xae\xf8\x0f\xae\xe8')
        self.assertEqual(cpu.assemble('A: /* infinite call */ call A'), b'\xe8\xfb\xff\xff\xff')

        # Test long code
        self.assertEqual(cpu.assemble(SHELLCODE_32), SHELLCODE_32_BYTES)

        # Test constant
        self.assertEqual(cpu.assemble(CONST_NASM), CONST_NASM_BYTES)

        # Test exception
        with self.assertRaises(OSError):
            cpu.assemble("invalid_insn eax, eax")
        with self.assertRaises(OSError):
            cpu.assemble("add eax, bx")

    def test_64bit_nasm(self):
        """Test assembler for Intel 64-bit nasm
        """
        if _is_windows:
            return # Skip windows

        cpu = CPU('intel', 64)
        cpu.assembler = 'nasm'

        # Test assembler
        self.assertEqual(cpu.assemble(''), b'')
        self.assertEqual(cpu.assemble('nop'), b'\x90')
        self.assertEqual(cpu.assemble('nop; nop'), b'\x90\x90')
        self.assertEqual(cpu.assemble('a:nop\nb:int3;nop'), b'\x90\xcc\x90')

        # Test minor assembly
        self.assertEqual(cpu.assemble('endbr64'), b'\xf3\x0f\x1e\xfa')
        self.assertEqual(cpu.assemble('lgdt [rdi]'), b'\x0f\x01\x17')
        self.assertEqual(cpu.assemble('mfence; sfence; lfence'),
                         b'\x0f\xae\xf0\x0f\xae\xf8\x0f\xae\xe8')
        self.assertEqual(cpu.assemble('A: /* infinite call */ call A'), b'\xe8\xfb\xff\xff\xff')

        # Test constant
        self.assertEqual(cpu.assemble(CONST_NASM), CONST_NASM_BYTES)

        # Test exception
        with self.assertRaises(OSError):
            cpu.assemble("invalid_insn eax, eax")
        with self.assertRaises(OSError):
            cpu.assemble("add rax, ebx")
