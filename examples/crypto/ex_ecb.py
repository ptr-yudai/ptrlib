#!/usr/bin/env python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from ptrlib.crypto.ecb import ecb_chosenplaintext

prefix = b"BEBEMYMY"
flag = b"The quick brown fox jumps over the lazy dog."


def encrypt(m):
    key = sha256(flag).digest()
    m = pad(prefix + m + flag, AES.block_size)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(m)


cracked = ecb_chosenplaintext(encrypt, prefix, len(flag))

print("===== Chosen Plaintext Attack =====")
print("Plain text: " + repr(cracked))
