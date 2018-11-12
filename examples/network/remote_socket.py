#!/usr/bin/env python
from ptrlib import *

# Establish connection
sock = Socket("www.example.com", 80)
sock.settimeout(1.0)
# Request header
sock.send("GET / HTTP/1.0\r\n")
sock.send("Host: www.example.com\r\n\r\n")
# Receive header
header = sock.recvuntil("\r\n\r\n")
# Receive HTML
html = sock.recvall()
sock.close()

print("===== Header =====")
print(header)
print("===== HTML =====")
print(html)
