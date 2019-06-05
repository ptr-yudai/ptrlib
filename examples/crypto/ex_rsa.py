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

def encrypt(pubkey, m):
    e, n = pubkey
    return pow(m, e, n)

def decrypt(privkey, c):
    d, n = privkey
    return pow(c, d, n)

# params, plaintext
pubkey, privkey = gen_params(1024)
e, n = pubkey
plain = b"The quick brown fox jumps over the lazy dog."
m = bytes_to_long(plain)
c = encrypt(pubkey, m)

assert m == decrypt(privkey, c)

# This is the function we have to prepare
def lsb_oracle(c):
    d, n = privkey
    return pow(c, d, n) & 1

m2 = lsb_leak_attack(lsb_oracle, n, e, c)
assert m2 == m
print("===== LSB Leak Attack =====")
print("Plain text: " + repr(long_to_bytes(m2)))
