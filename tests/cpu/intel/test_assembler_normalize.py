import os
import unittest
from logging import getLogger, FATAL
from ptrlib.cpu import CPU

_is_windows = os.name == 'nt'

class TestIntelAssemblerNormalize(unittest.TestCase):
    """Normalization-focused tests for Intel assembler backends.

    These tests ensure that _normalize_assembly() handles:
      - Size specifiers around memory operands (inserting 'ptr' for GAS)
      - Comma and bracket spacing normalization
      - Semicolon-based instruction splitting
      - // line comments and /* block comments */ removal
      - Case-insensitive size specifiers
    """
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)

    def test_gcc_size_ptr_insertion_qword(self):
        """qword [mem] vs qword ptr [mem] must assemble identically with GCC."""
        if _is_windows:
            return
        cpu = CPU('intel', 64)
        cpu.assembler = 'gcc'
        a = 'mov qword [rax], 0x1234'
        b = 'mov qword ptr [rax], 0x1234'
        self.assertEqual(cpu.assemble(a), cpu.assemble(b))

    def test_gcc_size_ptr_insertion_other_sizes(self):
        """byte/word/dword [mem] vs ... ptr [mem] must match with GCC."""
        if _is_windows:
            return
        cpu = CPU('intel', 64)
        cpu.assembler = 'gcc'
        pairs = [
            ('mov dword [rax], 0x11223344', 'mov dword ptr [rax], 0x11223344'),
            ('mov word [rax], 0x3344',      'mov word ptr [rax], 0x3344'),
            ('mov byte [rax], 0x22',        'mov byte ptr [rax], 0x22'),
        ]
        for a, b in pairs:
            self.assertEqual(cpu.assemble(a), cpu.assemble(b))

    def test_no_spurious_backslash_produced(self):
        """Ensure 'mov qword [rax], 1' assembles (no '\\[' introduced)."""
        if _is_windows:
            return
        cpu = CPU('intel', 64)
        cpu.assembler = 'gcc'
        # Should not raise OSError
        cpu.assemble('mov qword [rax], 1')

    def test_comma_and_bracket_spacing_mov(self):
        """mov rax,[rbx] variants should assemble identically."""
        if _is_windows:
            return
        for assembler in ('gcc', 'nasm'):
            cpu = CPU('intel', 64)
            cpu.assembler = assembler
            a = 'mov rax,[rbx]'
            b = 'mov rax, [ rbx ]'
            self.assertEqual(cpu.assemble(a), cpu.assemble(b))

    def test_bracket_tightening_with_lea(self):
        """[ rbx + 8 ] -> [rbx + 8] equivalence (no 'ptr' involved)."""
        if _is_windows:
            return
        for assembler in ('gcc', 'nasm'):
            cpu = CPU('intel', 64)
            cpu.assembler = assembler
            a = 'lea rax,[ rbx + 8 ]'
            b = 'lea rax, [rbx+8]'
            self.assertEqual(cpu.assemble(a), cpu.assemble(b))

    def test_line_and_block_comment_stripping(self):
        """'// ...' and '/* ... */' must be ignored by the tokenizer."""
        if _is_windows:
            return
        for assembler in ('gcc', 'nasm'):
            cpu = CPU('intel', 64)
            cpu.assembler = assembler
            code = 'nop // line\n/* block\n comment */ nop ; nop'
            baseline = 'nop\nnop\nnop'
            self.assertEqual(cpu.assemble(code), cpu.assemble(baseline))

    def test_semicolon_instruction_split(self):
        """'nop; nop ;nop' equals three nops after normalization."""
        if _is_windows:
            return
        for assembler in ('gcc', 'nasm'):
            cpu = CPU('intel', 64)
            cpu.assembler = assembler
            code = 'nop;   nop  ;  nop'
            baseline = 'nop\nnop\nnop'
            self.assertEqual(cpu.assemble(code), cpu.assemble(baseline))

    def test_whitespace_collapse(self):
        """Multiple spaces/tabs collapse and consistent comma spacing."""
        if _is_windows:
            return
        for assembler in ('gcc', 'nasm'):
            cpu = CPU('intel', 64)
            cpu.assembler = assembler
            code = '    mov     rax ,    [   rbx   +   0x10  ]   '
            baseline = 'mov rax, [rbx+0x10]'
            self.assertEqual(cpu.assemble(code), cpu.assemble(baseline))

    def test_size_keyword_case_insensitive(self):
        """Ensure case-insensitive match for size keywords for GCC path."""
        if _is_windows:
            return
        cpu = CPU('intel', 64)
        cpu.assembler = 'gcc'
        a = 'mov QWORD [rax], 1'
        b = 'mov qword ptr [rax], 1'
        self.assertEqual(cpu.assemble(a), cpu.assemble(b))


    def test_nasm_removes_ptr_keyword(self):
        """In NASM mode, 'ptr' should be removed; both forms must assemble identically."""
        if _is_windows:
            return
        cpu = CPU('intel', 64)
        cpu.assembler = 'nasm'
        pairs = [
            ('mov qword [rax], 0x1122334455667788', 'mov qword ptr [rax], 0x1122334455667788'),
            ('mov dword [rax], 0x11223344',         'mov dword ptr [rax], 0x11223344'),
            ('mov word [rax], 0x3344',              'mov word ptr [rax], 0x3344'),
            ('mov byte [rax], 0x22',                'mov byte ptr [rax], 0x22'),
        ]
        for a, b in pairs:
            self.assertEqual(cpu.assemble(a), cpu.assemble(b))

    def test_alias_nasm_function_handles_ptr(self):
        """The nasm() helper should also accept 'ptr' and normalize it away."""
        if _is_windows:
            return
        from ptrlib.cpu.assembler import nasm as nasm_asm
        a = nasm_asm('mov qword [rax], 1', bits=64)
        b = nasm_asm('mov qword ptr [rax], 1', bits=64)
        self.assertEqual(a, b)
