#!/usr/bin/env python3
from ptrlib import *

print(disasm(bytes.fromhex("e80600000048656c6c6f0058"), arch='intel'))
print('-'*10)
print(disasm(bytes.fromhex("31d28b042441"), arch='amd64'))
print('-'*10)
print(disasm(bytes.fromhex("4d31d40f1104243930"), arch='amd64'))
print('-'*10)
print(disasm(bytes.fromhex("4110a0e3ffffffeb021180e748656c6c6f2c20576f726c6421000000"), bits=32, arch='arm'))
print('-'*10)
print(disasm(bytes.fromhex("212888d20200009420000058"), arch='aarch64'))
