#!/usr/bin/env python
from ptrlib import *

sock = Socket("chall.pwnable.tw", 10100)
print(sock.recvline())

# Interactive mode
sock.interact()
