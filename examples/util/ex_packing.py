#!/usr/bin/env python
from ptrlib import *

print("p16(0xdead, 'big') = {}".format(p32(0xdead, byteorder='big')))
print("p16(0xdead) = {}".format(p32(0xdead)))
print("p32(0xdeadbeef) = {}".format(p32(0xdeadbeef)))
print("p64(0xdeadbeefcafebabe) = {}".format(p64(0xdeadbeefcafebabe)))
print("p32(3.14) = {}".format(p32(3.14)))
print("p64(3.14) = {}".format(p64(3.14)))

print("u16('\\xde\\xad', order='big') = {}".format(u16('\xde\xad', byteorder='big')))
print("u16('\\xde\\xad') = {}".format(u16('\xde\xad')))
print("u16('\\xde\\xad', signed=True) = {}".format(u16('\xde\xad', signed=True)))
print("u64('\\x1f\\x85\\xeb\\x51\\xb8\\x1e\\x09\\x40', type=float) = {}".format(u64(b"\x1f\x85\xeb\x51\xb8\x1e\x09\x40", type=float)))
