#!/usr/bin/env python
from ptrlib import *

elf = ELF("/bin/ls")

print(hex(elf.got("calloc")))
print(hex(elf.plt("calloc")))
print(hex(elf.plt("calloc")))
