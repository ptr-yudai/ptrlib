#!/usr/bin/env python
from ptrlib import *
from Crypto.Cipher import AES

# These functions are invisible, maybe over the internet
# We can encrypt and decrypt arbitrary messages,
# but we cannot decrypt given 
def encrypt(plain):
    key = 'Secret Password!'
    iv  = 'Initial Vector!!'
    pad = lambda s, bs: s + chr(bs - (len(s) % bs)) * (bs - (len(s) % bs))
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plain, AES.block_size))
def decrypt(cipher):
    key = 'Secret Password!'
    iv  = 'Initial Vector!!'
    unpad = lambda s: s[:-ord(s[-1])]
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted = aes.decrypt(cipher)
    # padding check
    if ord(decrypted[-1]) > 16:
        return None
    if decrypted[-1] * ord(decrypted[-1]) != decrypted[-ord(decrypted[-1]):]:
        return None
    return unpad(decrypted)

# Sample data
plain = "The quick brown fox jumps over the lazy dog."

cipher = encrypt(plain)
assert plain == decrypt(cipher)

# This is the function we have to prepare
def try_decrypt(cipher):
    if decrypt(cipher) is None:
        return False
    return True

cracked = padding_oracle_cbc(try_decrypt, cipher, AES.block_size, unknown='?', unpad=True)
print("Plain text: " + repr(cracked))
