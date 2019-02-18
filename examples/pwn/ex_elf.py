#!/usr/bin/env python
from ptrlib import *

#elf = ELF("./calc_pwnable.tw")
elf = ELF("./babyheap_fireshell")

print(elf.checksec())
