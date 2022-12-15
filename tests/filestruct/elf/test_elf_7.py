import unittest
from ptrlib.filestruct.elf import ELF
from logging import getLogger, FATAL


PATH_ELF = "./tests/test.bin/test_fsb.x64"

class TestELF7(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        self.elf = ELF(PATH_ELF)

    def test_plt(self):
        self.assertEqual(self.elf.plt('printf'), 0x400530)
        self.assertEqual(self.elf.plt('printf'), 0x400530) # test cache
        self.assertEqual(self.elf.plt('setbuf'), 0x400520)

    def test_got(self):
        self.assertEqual(self.elf.got('printf'), 0x601028)
        self.assertEqual(self.elf.got('printf'), 0x601028) # test cache
        self.assertEqual(self.elf.got('setbuf'), 0x601020)

    def test_section(self):
        self.elf.base = 0
        self.assertEqual(self.elf.section('.bss'), 0x601050)
        self.assertEqual(self.elf.section('.bss'), 0x601050) # test cache

    def test_security(self):
        self.assertEqual(self.elf.relro(), 1)
        self.assertEqual(self.elf.ssp(), False)
        self.assertEqual(self.elf.nx(), True)
        self.assertEqual(self.elf.pie(), False)
