import unittest
import os
from ptrlib.filestruct.elf import ELF
from logging import getLogger, FATAL


PATH_ELF = "./tests/test.bin/libc-2.35.i386.so"
BASE = 0x56555000

class TestELF10(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        self.elf = ELF(PATH_ELF)

    def test_symbol(self):
        self.elf.base = 0
        self.assertEqual(self.elf.symbol('system'), 0x50430)
        self.assertEqual(self.elf.symbol('system'), 0x50430) # test cache
        self.assertEqual(self.elf.symbol('__libc_system'), 0x50430)
        self.assertEqual(self.elf.symbol('_IO_2_1_stdout_'), 0x231d40)
        self.assertEqual(self.elf.symbol('_IO_stdfile_1_lock'), 0x2328a0)
        self.assertEqual(self.elf.symbol('_IO_stdfile_1_lock'), 0x2328a0) # test cache

        self.elf.base = BASE
        self.assertEqual(self.elf.symbol('system'), BASE + 0x50430)
        self.assertEqual(self.elf.symbol('system'), BASE + 0x50430)
        self.assertEqual(self.elf.symbol('__libc_system'), BASE + 0x50430)
        self.assertEqual(self.elf.symbol('_IO_2_1_stdout_'), BASE + 0x231d40)
        self.assertEqual(self.elf.symbol('_IO_stdfile_1_lock'), BASE + 0x2328a0)

    def test_search(self):
        self.elf.base = 0
        it = self.elf.search('A')
        self.assertEqual(next(it), 0x42c)
        self.assertEqual(next(it), 0x80c)
        self.assertEqual(next(it), 0xda0)
        self.assertEqual(next(self.elf.search('A', writable=True)), 0x22fb8c)
        self.assertEqual(next(self.elf.find(b'/bin/sh\0')), 0x1c4de8)

        self.elf.base = BASE
        it = self.elf.search('A')
        self.assertEqual(next(it), BASE + 0x42c)
        self.assertEqual(next(it), BASE + 0x80c)
        self.assertEqual(next(it), BASE + 0xda0)
        self.assertEqual(next(self.elf.search('A', writable=True)), BASE + 0x22fb8c)
        self.assertEqual(next(self.elf.find(b'/bin/sh\0')), BASE + 0x1c4de8)

    def test_main_arena(self):
        self.elf.base = 0
        self.assertEqual(self.elf.main_arena(), 0x231760)
        self.assertEqual(self.elf.main_arena(use_symbol=False), 0x231760)
        self.elf.base = BASE
        self.assertEqual(self.elf.main_arena(), BASE + 0x231760)
        self.assertEqual(self.elf.main_arena(use_symbol=False), BASE + 0x231760)

    def test_security(self):
        self.assertEqual(self.elf.relro(), 2)
        self.assertEqual(self.elf.ssp(), True)
        self.assertEqual(self.elf.nx(), True)
        self.assertEqual(self.elf.pie(), True)
