from ptrlib import *
import os

SALT = os.urandom(8)
known_message = 'Hello'
append_message = "World"

# MD5
m = MD5()
m.update(SALT + known_message)
known_hash = m.hexdigest()
new_hash, data = length_extension(
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
new_hash, data = length_extension(
    SHA1, len(SALT), known_hash, known_message, append_message
)
m.reset()
m.update(SALT + data)
print("========== SHA-1 ==========")
print("known_sha1 = " + known_hash)
print("new_sha1   = " + new_hash)
print("*new_sha1  = " + m.hexdigest())
print("data       = " + repr(data))
