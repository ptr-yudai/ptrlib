#!/usr/bin/env python
from ptrlib import *
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

def gen_params(keysize, e=65537):
    p = getPrime(keysize)
    q = getPrime(keysize)
    n = p * q
    phi = (p-1) * (q-1)
    d = inverse(e, phi)
    return (e, n), (d, n)

m = 0xdeadbeefcafebabe
e = 3
pairs = []
for i in range(e):
    pub, priv = gen_params(128, e)
    c = pow(m, pub[0], pub[1])
    pairs.append((c, pub[1]))

print("Plaintext: {}".format(m))
print("Decrypted: {}".format(hastads_broadcast_attack(e, pairs)))
