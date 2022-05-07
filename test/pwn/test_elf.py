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
        self.new64 = ELF("./test/pwn/testbin/test_plt.x64")
        self.libc64 = ELF("./test/pwn/testbin/libc-2.27.so")
        getLogger("ptrlib").setLevel(FATAL)

    def test_got(self):
        self.assertEqual(self.elf32.got('printf'), 0x0804a010)
        self.assertEqual(self.elf32.got('printf'), 0x0804a010) # cache
        self.assertEqual(self.elf64.got('printf'), 0x00601028)
        self.assertEqual(self.pie32.got('read'), 0x00001fdc)
        self.assertEqual(self.pie64.got('read'), 0x00200fd0)
        self.assertEqual(self.new64.got('free'), 0x404018)
        self.pie32.set_base(0x55554000)
        self.pie64.set_base(0x555555554000)
        self.assertEqual(self.pie32.got('read'),
                         0x55554000 + 0x00001fdc)
        self.assertEqual(self.pie64.got('read'),
                         0x555555554000 + 0x00200fd0)
        self.pie32.set_base()
        self.pie64.set_base()

    def test_plt(self):
        self.assertEqual(self.elf32.plt('printf'), 0x08048390)
        self.assertEqual(self.elf32.plt('printf'), 0x08048390) # cache
        self.assertEqual(self.elf64.plt('printf'), 0x00400530)
        self.assertEqual(self.pie32.plt('read'), 0x00000410)
        self.assertEqual(self.pie64.plt('read'), 0x000005d0)
        self.assertEqual(self.new64.plt('free'), 0x00401140)
        self.pie32.set_base(0x55554000)
        self.pie64.set_base(0x555555554000)
        self.assertEqual(self.pie32.plt('read'),
                         0x55554000 + 0x00000410)
        self.assertEqual(self.pie64.plt('read'),
                         0x555555554000 + 0x000005d0)
        self.pie32.set_base()
        self.pie64.set_base()

    def test_section(self):
        self.assertEqual(self.elf32.section('.bss'), 0x0804a028)
        self.assertEqual(self.elf64.section('.bss'), 0x00601050)
        self.assertEqual(self.pie32.section('.bss'), 0x00002008)
        self.assertEqual(self.pie64.section('.bss'), 0x00201010)
        self.pie32.set_base(0x55554000)
        self.pie64.set_base(0x555555554000)
        self.assertEqual(self.pie32.section('.bss'),
                         0x55554000 + 0x00002008)
        self.assertEqual(self.pie64.section('.bss'),
                         0x555555554000 + 0x00201010)
        self.pie32.set_base()
        self.pie64.set_base()

    def test_search(self):
        self.assertEqual(next(self.elf32.search("A")),
                         0x80481a1)
        self.assertEqual(next(self.elf32.search("\x00", writable=True)),
                         0x8049f0d)
        self.assertEqual(next(self.elf32.search("\xcc", executable=True)),
                         0x8048698)
        self.assertEqual(next(self.elf64.search("A")),
                         0x4006e0)
        self.assertEqual(next(self.elf64.search("\x00", writable=True)),
                         0x600e13)
        self.assertEqual(next(self.elf64.search("\x77", executable=True)),
                         0x400829)
        self.assertEqual(next(self.pie32.search("A")),
                         0x788)
        self.assertEqual(next(self.pie32.search("\x00", writable=True)),
                         0x1ed2)
        self.assertEqual(next(self.pie32.search("\x77", executable=True)),
                         0x1ec)
        self.assertEqual(next(self.pie64.search("A")),
                         0x780)
        self.assertEqual(next(self.pie64.search("\x00", writable=True)),
                         0x200daa)
        g = self.pie64.search("\x77", executable=True)
        self.assertEqual(next(g), 0x3d2)
        self.pie64.set_base(0x555555540000)
        self.assertEqual(next(g), 0x555555540000 + 0x8a1)
        self.pie64.set_base()

    def test_libc(self):
        self.assertEqual(self.libc64.main_arena(), 0x3ebc40)
        self.assertEqual(next(self.libc64.search("/bin/sh")), 0x1b3e9a)
        self.assertEqual(next(self.libc64.search("/bin/sh")),
                         next(self.libc64.find("/bin/sh")))
        self.assertEqual(self.libc64.symbol("_IO_2_1_stdout_"), 0x3ec760)
        self.assertEqual(self.libc64.symbol("system"), 0x4f440)
        self.libc64.set_base(0x7ffff79e2000)
        self.assertEqual(self.libc64.main_arena(),
                         0x7ffff79e2000 + 0x3ebc40)
        self.assertEqual(next(self.libc64.search("/bin/sh")),
                         0x7ffff79e2000 + 0x1b3e9a)
        self.assertEqual(self.libc64.symbol("system"),
                         0x7ffff79e2000 + 0x4f440)
        self.libc64.set_base()

        libc231 = ELF("./test/pwn/testbin/libc-2.31.so")
        libc234 = ELF("./test/pwn/testbin/libc-2.34.so")
        self.assertEqual(libc231.main_arena(), 0x1ecb80)
        self.assertEqual(libc234.main_arena(), 0x218c60)
        libc231.close()
        libc234.close()

    # TODO: Add test for gadget

    def test_security(self):
        self.assertEqual(self.elf32.ssp(), False)
        self.assertEqual(self.elf64.ssp(), False)
        self.assertEqual(self.pie32.ssp(), True)
        self.assertEqual(self.pie64.ssp(), True)
        self.assertEqual(self.elf32.pie(), False)
        self.assertEqual(self.elf64.pie(), False)
        self.assertEqual(self.pie32.pie(), True)
        self.assertEqual(self.pie64.pie(), True)
        self.assertEqual(self.elf32.relro(), 1)
        self.assertEqual(self.elf64.relro(), 1)
        self.assertEqual(self.pie32.relro(), 2)
        self.assertEqual(self.pie64.relro(), 2)
        self.assertEqual(self.elf32.nx(), True)
        self.assertEqual(self.elf64.nx(), True)
        self.assertEqual(self.pie32.nx(), True)
        self.assertEqual(self.pie64.nx(), True)

    def tearDown(self):
        self.elf32.close()
        self.elf64.close()
        self.pie32.close()
        self.pie64.close()
        self.new64.close()
        self.libc64.close()

if __name__ == '__main__':
    unittest.main()
