#!/usr/bin/env python
from ptrlib import *
from Crypto.Cipher import AES

# These functions are invisible, maybe over the internet
# We can encrypt and decrypt arbitrary messages,
# but we cannot decrypt a given ciphertext.
def encrypt(plain):
    key = b'\xde\xad\xbe\xef\xca\xfe\xba\xbe\x01\x23\x45\x67\x89\xab\xcd\xef'
    iv  = b'd34db33fc4f3b4b3'
    pad = lambda s, bs: s + bytes([bs - (len(s) % bs)]) * (bs - (len(s) % bs))
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plain, AES.block_size))

def decrypt(cipher):
    key = b'\xde\xad\xbe\xef\xca\xfe\xba\xbe\x01\x23\x45\x67\x89\xab\xcd\xef'
    iv  = b'd34db33fc4f3b4b3'
    unpad = lambda s: s[:-s[-1]]
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes.decrypt(cipher)
    # padding check
    if decrypted[-1] > 16:
        return None
    if bytes([decrypted[-1]]) * decrypted[-1] != decrypted[-decrypted[-1]:]:
        return None
    return unpad(decrypted)

# Sample data
plain = b"The quick brown fox jumps over the lazy dog."

cipher = encrypt(plain)
assert plain == decrypt(cipher)

# This is the function we have to prepare
def try_decrypt(cipher):
    if decrypt(cipher) is None:
        return False
    return True

cracked = padding_oracle(
    try_decrypt,
    cipher,
    AES.block_size,
    unknown='?',
    unpad=True
)
print("===== Padding Oracle Attack =====")
print("Plain text: " + repr(cracked))

cracked = padding_oracle(
    try_decrypt,
    cipher,
    AES.block_size,
    unknown='?',
    unpad=True,
    iv = 'd34db33fc4f3b4b3'
)
print("===== Padding Oracle Attack (with IV) =====")
print("Plain text: " + repr(cracked))

