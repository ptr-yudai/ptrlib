#!/usr/bin/env python
from ptrlib import *

# 64-bit binary
elf = ELF("sample/test1")
print(hex(elf.got("read")))
print(hex(elf.plt("read")))
print(hex(elf.symbol("main")))

# 32-bit binary
elf = ELF("sample/test2")
print(hex(elf.got("read")))
print(hex(elf.plt("read")))
print(hex(elf.symbol("main")))
