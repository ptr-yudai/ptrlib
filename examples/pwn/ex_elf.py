#!/usr/bin/env python
from ptrlib import *

elf = ELF("/lib32/libc.so.6")
print("'/bin/sh' at 0x{:x}".format(next(elf.find("/bin/sh"))))
print("main_arena at 0x{:x}".format(elf.main_arena()))
print("__malloc_hook at 0x{:x}".format(elf.symbol('__malloc_hook')))

elf = ELF("/lib/x86_64-linux-gnu/libc.so.6")
print("'/bin/sh' at 0x{:x}".format(next(elf.find("/bin/sh"))))
print("main_arena at 0x{:x}".format(elf.main_arena()))
