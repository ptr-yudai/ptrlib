from ptrlib import *
import os

SALT = os.urandom(8)
known_message = 'Hello'
m = MD5()
m.update(SALT + known_message)
known_md5 = m.hexdigest()
append_message = "World"

new_md5, data = length_extension(
    MD5,
    len(SALT),
    known_md5,
    known_message,
    append_message
)
m.reset()
m.update(SALT + data)

print("known_md5 = " + known_md5)
print("new_md5   = " + new_md5)
print("*new_md5  = " + m.hexdigest())
print("data      = " + repr(data))
