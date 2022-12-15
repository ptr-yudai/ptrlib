#!/usr/bin/env python
from ptrlib import *

# 32-bit libc
elf = ELF("/lib32/libc.so.6")
g = elf.gadget("pop edi; ret")
print("pop_edi@" + hex(next(g)))
print("pop_edi@" + hex(next(g)))
print("pop_edi@" + hex(next(g)))

# 64-bit libc
elf = ELF("/lib/x86_64-linux-gnu/libc.so.6")
g = elf.gadget("mov rax, r8; pop r12; ret")
print("mov_rax_r8_pop_r12@" + hex(next(g)))

elf.set_base(0x555555554000)
g = elf.gadget("pop rdi; ret")
print("pop_rdi@" + hex(next(g)))
print("pop_rdi@" + hex(next(g)))
print("pop_rdi@" + hex(next(g)))
