#!/usr/bin/env python
from ptrlib import *
import os

SALT = os.urandom(8)
known_message = b'Hello'
append_message = b'World'

# MD5
m = MD5()
m.update(SALT + known_message)
known_hash = m.hexdigest()
new_hash, data = lenext(
    MD5, len(SALT), known_hash, known_message, append_message
)
m.reset()
m.update(SALT + data)
print("========== MD5 ==========")
print("known_md5 = " + known_hash)
print("new_md5   = " + new_hash)
print("*new_md5  = " + m.hexdigest())
print("data      = " + repr(data))

# SHA-1
m = SHA1()
m.update(SALT + known_message)
known_hash = m.hexdigest()
new_hash, data = lenext(
    SHA1, len(SALT), known_hash, known_message, append_message
)
m.reset()
m.update(SALT + data)
print("========== SHA-1 ==========")
print("known_sha1 = " + known_hash)
print("new_sha1   = " + new_hash)
print("*new_sha1  = " + m.hexdigest())
print("data       = " + repr(data))

# SHA-256
m = SHA256()
m.update(SALT + known_message)
known_hash = m.hexdigest()
new_hash, data = lenext(
    SHA256, len(SALT), known_hash, known_message, append_message
)
m.reset()
m.update(SALT + data)
print("========== SHA-256 ==========")
print("known_sha256 = " + known_hash)
print("new_sha256   = " + new_hash)
print("*new_sha256  = " + m.hexdigest())
print("data       = " + repr(data))
