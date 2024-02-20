import unittest
import os
from ptrlib.filestruct.elf import ELF
from logging import getLogger, FATAL


PATH_ELF = "./tests/test.bin/libc-2.35.so"
BASE = 0x7fffdeadb000

class TestELF9(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        self.elf = ELF(PATH_ELF)

    def test_symbol(self):
        self.elf.base = 0
        self.assertEqual(self.elf.symbol('system'), 0x50d70)
        self.assertEqual(self.elf.symbol('system'), 0x50d70) # test cache
        self.assertEqual(self.elf.symbol('__libc_system'), 0x50d70)
        self.assertEqual(self.elf.symbol('_IO_2_1_stdout_'), 0x21b780)

        self.elf.base = BASE
        self.assertEqual(self.elf.symbol('system'), BASE + 0x50d70)
        self.assertEqual(self.elf.symbol('system'), BASE + 0x50d70)
        self.assertEqual(self.elf.symbol('__libc_system'), BASE + 0x50d70)
        self.assertEqual(self.elf.symbol('_IO_2_1_stdout_'), BASE + 0x21b780)

    def test_search(self):
        self.elf.base = 0
        it = self.elf.search('A')
        self.assertEqual(next(it), 0x108)
        self.assertEqual(next(it), 0x110)
        self.assertEqual(next(it), 0x3e)
        self.assertEqual(next(self.elf.search('A', writable=True)), 0x219529)
        self.assertEqual(next(self.elf.find(b'/bin/sh\0')), 0x1d8678)

        self.elf.base = BASE
        it = self.elf.search('A')
        self.assertEqual(next(it), BASE + 0x108)
        self.assertEqual(next(it), BASE + 0x110)
        self.assertEqual(next(it), BASE + 0x3e)
        self.assertEqual(next(self.elf.search('A', writable=True)), BASE + 0x219529)
        self.assertEqual(next(self.elf.find(b'/bin/sh\0')), BASE + 0x1d8678)

    def test_main_arena(self):
        self.elf.base = 0
        self.assertEqual(self.elf.main_arena(), 0x21ac80)
        self.elf.base = BASE
        self.assertEqual(self.elf.main_arena(), BASE + 0x21ac80)

    def test_security(self):
        self.assertEqual(self.elf.relro(), 1)
        self.assertEqual(self.elf.ssp(), True)
        self.assertEqual(self.elf.nx(), True)
        self.assertEqual(self.elf.pie(), True)
