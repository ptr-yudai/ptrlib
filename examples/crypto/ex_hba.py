#!/usr/bin/env python
""" Hastad's Broadcast Attack """
from ptrlib import *

m = 0xdeadbeefcafebabe
e = 3

pairs = []
for i in range(e):
    p, q = gen_prime(256), gen_prime(256)
    n = p * q
    c = pow(m, e, n)
    pairs.append((c, n))

print("plaintext: {}".format(hex(m)))
print("decrypted: {}".format(hex(hastads_broadcast_attack(e, pairs))))
