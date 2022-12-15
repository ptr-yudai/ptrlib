import unittest
from ptrlib.filestruct.elf import ELF
from logging import getLogger, FATAL


PATH_ELF = "./tests/test.bin/libc-2.31.so"
BASE = 0x7fffdeadb000

class TestELF2(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        self.elf = ELF(PATH_ELF)

    def test_symbol(self):
        self.elf.base = 0
        self.assertEqual(self.elf.symbol('system'), 0x522c0)
        self.assertEqual(self.elf.symbol('system'), 0x522c0) # test cache
        self.assertEqual(self.elf.symbol('__libc_system'), 0x522c0)
        self.assertEqual(self.elf.symbol('_IO_2_1_stdout_'), 0x1ed6a0)

        self.elf.base = BASE
        self.assertEqual(self.elf.symbol('system'), BASE + 0x522c0)
        self.assertEqual(self.elf.symbol('system'), BASE + 0x522c0)
        self.assertEqual(self.elf.symbol('__libc_system'), BASE + 0x522c0)
        self.assertEqual(self.elf.symbol('_IO_2_1_stdout_'), BASE + 0x1ed6a0)

    def test_search(self):
        self.elf.base = 0
        it = self.elf.search('A')
        self.assertEqual(next(it), 25)
        self.assertEqual(next(it), 998)
        self.assertEqual(next(it), 1181)
        self.assertEqual(next(self.elf.search('A', writable=True)), 2004929)
        self.assertEqual(next(self.elf.find(b'/bin/sh\0')), 1787325)

        self.elf.base = BASE
        it = self.elf.search('A')
        self.assertEqual(next(it), BASE + 25)
        self.assertEqual(next(it), BASE + 998)
        self.assertEqual(next(it), BASE + 1181)
        self.assertEqual(next(self.elf.search('A', writable=True)), BASE + 2004929)
        self.assertEqual(next(self.elf.find(b'/bin/sh\0')), BASE + 1787325)

    def test_main_arena(self):
        self.elf.base = 0
        self.assertEqual(self.elf.main_arena(), 0x1ecb80)
        self.elf.base = BASE
        self.assertEqual(self.elf.main_arena(), BASE + 0x1ecb80)

    def test_security(self):
        self.assertEqual(self.elf.relro(), 1)
        self.assertEqual(self.elf.ssp(), True)
        self.assertEqual(self.elf.nx(), True)
        self.assertEqual(self.elf.pie(), True)
