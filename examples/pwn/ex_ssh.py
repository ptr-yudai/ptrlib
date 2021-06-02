#!/usr/bin/env python
from ptrlib import *

# Connect with raw credential
sock = SSH("example.com", 22, username="ubuntu", password="password123")
sock.sendlineafter("$", "ls")
while True:
    try:
        sock.recvline(timeout=1)
    except TimeoutError:
        break
sock.close()

# Connect with identity file
sock = SSH("example.com", 22, username="ubuntu", identity="~/id_rsa")
sock.sendlineafter("$", "ls")
while True:
    try:
        sock.recvline(timeout=1)
    except TimeoutError:
        break
sock.close()
