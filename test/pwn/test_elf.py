import unittest
import os
from ptrlib import ELF
from logging import getLogger, FATAL

class TestELF(unittest.TestCase):
    def setUp(self):
        self.elf32 = ELF("./test/pwn/testbin/test_fsb.x86")
        self.elf64 = ELF("./test/pwn/testbin/test_fsb.x64")
        self.pie32 = ELF("./test/pwn/testbin/test_echo.x86")
        self.pie64 = ELF("./test/pwn/testbin/test_echo.x64")
        getLogger("ptrlib").setLevel(FATAL)

    def test_got(self):
        self.assertEqual(self.elf32.got('printf'), 0x0804a010)
        self.assertEqual(self.elf64.got('printf'), 0x00601028)
        self.assertEqual(self.pie32.got('read'), 0x00001fdc)
        self.assertEqual(self.pie64.got('read'), 0x00200fd0)

    def test_plt(self):
        self.assertEqual(self.elf32.plt('printf'), 0x08048390)
        self.assertEqual(self.elf64.plt('printf'), 0x00400530)
        self.assertEqual(self.pie32.plt('read'), 0x00000410)
        self.assertEqual(self.pie64.plt('read'), 0x000005d0)

    def tearDown(self):
        self.elf32.close()
        self.elf64.close()
        self.pie32.close()
        self.pie64.close()

if __name__ == '__main__':
    unittest.main()
