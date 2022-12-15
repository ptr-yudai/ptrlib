import unittest
from ptrlib.filestruct.elf import ELF
from logging import getLogger, FATAL


PATH_ELF = "./tests/test.bin/test_echo.x64"
BASE = 0x555555554000

class TestELF5(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        self.elf = ELF(PATH_ELF)

    def test_plt(self):
        self.elf.base = 0
        self.assertEqual(self.elf.plt('read'), 0x5d0)
        self.assertEqual(self.elf.plt('read'), 0x5d0) # test cache
        self.assertEqual(self.elf.plt('__stack_chk_fail'), 0x5c0)
        self.elf.base = BASE
        self.assertEqual(self.elf.plt('read'), BASE + 0x5d0)
        self.assertEqual(self.elf.plt('__stack_chk_fail'), BASE + 0x5c0)

    def test_got(self):
        self.elf.base = 0
        self.assertEqual(self.elf.got('read'), 0x200fd0)
        self.assertEqual(self.elf.got('read'), 0x200fd0) # test cache
        self.assertEqual(self.elf.got('__stack_chk_fail'), 0x200fc8)
        self.elf.base = BASE
        self.assertEqual(self.elf.got('read'), BASE + 0x200fd0)
        self.assertEqual(self.elf.got('__stack_chk_fail'), BASE + 0x200fc8)

    def test_section(self):
        self.elf.base = 0
        self.assertEqual(self.elf.section('.bss'), 0x201010)
        self.assertEqual(self.elf.section('.bss'), 0x201010) # test cache
        self.elf.base = BASE
        self.assertEqual(self.elf.section('.bss'), BASE + 0x201010)

    def test_security(self):
        self.assertEqual(self.elf.relro(), 2)
        self.assertEqual(self.elf.ssp(), True)
        self.assertEqual(self.elf.nx(), True)
        self.assertEqual(self.elf.pie(), True)
