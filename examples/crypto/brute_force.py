#!/usr/bin/env python
from ptrlib import *
import string

known_hash = "165d3d525f6d0cbd55e42cc3058cafcc".decode("hex")
table = string.ascii_letters

m = MD5()
password_list = brute_force_attack(3, table_len=len(table))
for pattern in password_list:
    password = brute_force_pattern(pattern, table=table)
    m.update(password)
    if m.digest() == known_hash:
        print("Found the password!")
        print("Password: " + password)
        break
    m.reset()
