import unittest
import os
from ptrlib.filestruct.elf import ELF
from logging import getLogger, FATAL


PATH_ELF = "./tests/test.bin/libc-2.34.so"
BASE = 0x7fffdeadb000

class TestELF3(unittest.TestCase):
    def setUp(self):
        getLogger("ptrlib").setLevel(FATAL)
        self.elf = ELF(PATH_ELF)

    def test_symbol(self):
        self.elf.base = 0
        self.assertEqual(self.elf.symbol('system'), 0x54ae0)
        self.assertEqual(self.elf.symbol('system'), 0x54ae0) # test cache
        self.assertEqual(self.elf.symbol('__libc_system'), 0x54ae0)
        self.assertEqual(self.elf.symbol('_IO_2_1_stdout_'), 0x219760)
        self.assertEqual(self.elf.symbol('_IO_stdfile_1_lock'), 0x21b730)
        self.assertEqual(self.elf.symbol('_IO_stdfile_1_lock'), 0x21b730) # test cache

        self.elf.base = BASE
        self.assertEqual(self.elf.symbol('system'), BASE + 0x54ae0)
        self.assertEqual(self.elf.symbol('system'), BASE + 0x54ae0)
        self.assertEqual(self.elf.symbol('__libc_system'), BASE + 0x54ae0)
        self.assertEqual(self.elf.symbol('_IO_2_1_stdout_'), BASE + 0x219760)
        self.assertEqual(self.elf.symbol('_IO_stdfile_1_lock'), BASE + 0x21b730)

    def test_search(self):
        self.elf.base = 0
        it = self.elf.search('A')
        self.assertEqual(next(it), 2600)
        self.assertEqual(next(it), 2784)
        self.assertEqual(next(it), 3192)
        self.assertEqual(next(self.elf.search('A', writable=True)), 2187072)
        self.assertEqual(next(self.elf.find(b'/bin/sh\0')), 1948858)

        self.elf.base = BASE
        it = self.elf.search('A')
        self.assertEqual(next(it), BASE + 2600)
        self.assertEqual(next(it), BASE + 2784)
        self.assertEqual(next(it), BASE + 3192)
        self.assertEqual(next(self.elf.search('A', writable=True)), BASE + 2187072)
        self.assertEqual(next(self.elf.find(b'/bin/sh\0')), BASE + 1948858)

    def test_read(self):
        # syscall function
        start = 0x121930
        size = 0x37
        code = b"\xf3\x0f\x1e\xfaH\x89\xf8H\x89\xf7H\x89\xd6H\x89\xcaM\x89\xc2M\x89\xc8L\x8bL$\x08\x0f\x05H=\x01\xf0\xff\xffs\x01\xc3H\x8b\r\xb3d\x0f\x00\xf7\xd8d\x89\x01H\x83\xc8\xff\xc3"
        self.assertEqual(self.elf.read(start, size), code)
        # "/bin/sh"
        start = 1948858
        self.assertEqual(self.elf.read(start, 8), b"/bin/sh\0")

    def test_main_arena(self):
        self.elf.base = 0
        self.assertEqual(self.elf.main_arena(), 0x218c60)
        self.assertEqual(self.elf.main_arena(use_symbol=False), 0x218c60)
        self.elf.base = BASE
        self.assertEqual(self.elf.main_arena(), BASE + 0x218c60)
        self.assertEqual(self.elf.main_arena(use_symbol=False), BASE + 0x218c60)

    def test_security(self):
        self.assertEqual(self.elf.relro(), 1)
        self.assertEqual(self.elf.ssp(), True)
        self.assertEqual(self.elf.nx(), True)
        self.assertEqual(self.elf.pie(), True)
