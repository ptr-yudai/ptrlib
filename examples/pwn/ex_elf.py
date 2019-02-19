#!/usr/bin/env python
from ptrlib import *

elf = ELF("/lib/libc.so.6")
print(elf.checksec())

elf = ELF("binary/calc_pwnable.tw")
print(elf.checksec())

elf = ELF("binary/babyheap_fireshell")
print(elf.checksec())

elf = ELF("binary/sandbox_interkosenctf")
print(elf.checksec())

elf = ELF("binary/tcache_tear_pwnable.tw")
print(elf.checksec())

#print(hex(elf.symbol("memset")))
