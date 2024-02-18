import unittest
import os
from ptrlib.filestruct.elf import ELF
from logging import getLogger, FATAL

_is_windows = os.name == 'nt'


PATH_ELF = "./tests/test.bin/test_plt.x64"

class TestELF8(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        if _is_windows:
            self.skipTest("This test is intended for the Linux platform")
        self.elf = ELF(PATH_ELF)

    def test_plt(self):
        self.assertEqual(self.elf.plt('free'), 0x401140)
        self.assertEqual(self.elf.plt('free'), 0x401140) # test cache

    def test_got(self):
        self.assertEqual(self.elf.got('free'), 0x404018)
        self.assertEqual(self.elf.got('free'), 0x404018) # test cache
