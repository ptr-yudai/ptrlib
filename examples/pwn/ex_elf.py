#!/usr/bin/env python
from ptrlib import *

# 32-bit libc
elf = ELF("/lib32/libc.so.6") # who uses this btw?
print("'/bin/sh' at 0x{:x}".format(
    next(elf.find("/bin/sh")) # search for string
))
print("main_arena at 0x{:x}".format(
    elf.main_arena() # main_arena
))
print("__malloc_hook at 0x{:x}".format(
    elf.symbol('__malloc_hook') # symbol
))

# 64-bit libc
elf = ELF("/lib/x86_64-linux-gnu/libc.so.6")
print("'/bin/sh' at 0x{:x}".format(
    next(elf.find("/bin/sh")) # search for string
))
print("main_arena at 0x{:x}".format(
    elf.main_arena() # main_arena
))

elf.set_base(0x555555554020) # shows error
elf.set_base(0x555555554000)
print("main_arena at 0x{:x}".format(
    elf.main_arena()
))
