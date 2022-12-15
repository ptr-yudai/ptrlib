#!/usr/bin/env python
from ptrlib import *

# 64-bit binary
elf = ELF("sample/test-robot.x64")
print(hex(elf.got("read")))
print(hex(elf.plt("read")))
print(hex(elf.symbol("main")))

# 32-bit binary
elf = ELF("sample/test-ret2dl.relro.x86")
print(hex(elf.got("read")))
print(hex(elf.plt("read")))
print(hex(elf.symbol("main")))
