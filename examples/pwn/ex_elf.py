#!/usr/bin/env python
from ptrlib import *

elf = ELF("binary/calc_pwnable.tw")
print(elf.checksec())

elf = ELF("binary/babyheap_fireshell")
print(elf.checksec())

elf = ELF("binary/sandbox_interkosenctf")
print(elf.checksec())
